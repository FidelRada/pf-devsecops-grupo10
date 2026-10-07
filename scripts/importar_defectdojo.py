#!/usr/bin/env python3
"""Importa los reportes JSON del pipeline en DefectDojo (API v2).

Subcomandos:
  pipeline              reimporta los cuatro reportes del pipeline y adjunta bom.json y
                        gate.json al Engagement (estos dos no generan hallazgos).
  modelo-amenazas       crea el Engagement del modelo de amenazas y adjunta sus archivos.
  verificacion-parsers  importa los reportes de ejemplo del docente y el SBOM del proyecto
                        en un Product aparte, para comprobar que los parsers los aceptan.

Cada reporte se reimporta con POST /api/v2/reimport-scan/ y el parser correcto, en un
orden fijo: Semgrep -> SCA -> imagen -> Conftest. SCA va antes que la imagen para que
la deduplicación de DefectDojo marque como duplicados, en el Test de imagen, los
hallazgos de librerías Java que ya reportó el SBOM.

Configuración por variables de entorno:
  DEFECTDOJO_URL      p. ej. http://127.0.0.1:8080
  DEFECTDOJO_API_KEY  token de la API (nunca se imprime)
  GITHUB_RUN_ID, GITHUB_SHA, GITHUB_REF_NAME, GITHUB_SERVER_URL, GITHUB_REPOSITORY

Códigos de salida: 0 correcto; 1 error de la API o de red; 2 reporte o configuración faltante.
Solo usa la biblioteca estándar de Python 3.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import mimetypes
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from pathlib import Path

EXIT_OK = 0
EXIT_API = 1
EXIT_ENTRADA = 2

PRODUCT_TYPE = "Proyecto Final G10"
PRODUCT = "spring-boot-webapi-secure"
ENGAGEMENT_CI = "Pipeline CI/CD (main)"
ENGAGEMENT_TM = "Modelado de amenazas – Caso 5 Banca Móvil"
PRODUCT_EJEMPLOS = "Reportes de ejemplo del docente"
ENGAGEMENT_PARSERS = "Verificación de parsers"
REPOSITORIO = "https://github.com/FidelRada/pf-devsecops-grupo10"
# Archivos del pipeline que se adjuntan al Engagement en lugar de importarse:
# bom.json no trae vulnerabilidades y gate.json es un formato propio sin parser.
ADJUNTOS_PIPELINE = ("bom.json", "gate.json")

INTENTOS = 3
ESPERA_BASE = float(os.environ.get("DEFECTDOJO_ESPERA_BASE", "2"))
TIMEOUT = 300


class ErrorEntrada(Exception):
    """Falta un reporte o un dato de configuración."""


class ErrorApi(Exception):
    """DefectDojo respondió con un error o no fue posible conectarse."""


@dataclass
class Configuracion:
    url: str
    token: str = field(repr=False)
    product_type: str = PRODUCT_TYPE
    product: str = PRODUCT
    engagement: str = ENGAGEMENT_CI
    build_id: str = ""
    commit: str = ""
    rama: str = ""
    repo_uri: str = ""

    def __repr__(self) -> str:  # el token nunca aparece
        return f"Configuracion(url={self.url!r}, product={self.product!r}, engagement={self.engagement!r}, token=***)"

    @classmethod
    def desde_entorno(cls, entorno=None) -> "Configuracion":
        e = os.environ if entorno is None else entorno
        url = e.get("DEFECTDOJO_URL", "").rstrip("/")
        token = e.get("DEFECTDOJO_API_KEY", "")
        if not url:
            raise ErrorEntrada("falta la variable DEFECTDOJO_URL")
        if not token:
            raise ErrorEntrada("falta la variable DEFECTDOJO_API_KEY")
        if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
            raise ErrorEntrada("DEFECTDOJO_URL debe empezar con http:// o https://")
        servidor = e.get("GITHUB_SERVER_URL", "https://github.com")
        repo = e.get("GITHUB_REPOSITORY", "")
        return cls(
            url=url,
            token=token,
            build_id=e.get("GITHUB_RUN_ID", ""),
            commit=e.get("GITHUB_SHA", ""),
            rama=e.get("GITHUB_REF_NAME", ""),
            repo_uri=f"{servidor}/{repo}" if repo else "",
        )


@dataclass
class Reporte:
    herramienta: str
    scan_type: str
    test_title: str
    ruta: Path

    def validar(self) -> None:
        if not self.ruta.is_file():
            raise ErrorEntrada(f"reporte faltante: {self.ruta}")
        try:
            texto = self.ruta.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise ErrorEntrada(f"no se pudo leer {self.ruta}: {exc}") from exc
        if not texto.strip():
            raise ErrorEntrada(f"reporte vacío: {self.ruta}")
        try:
            json.loads(texto)
        except json.JSONDecodeError as exc:
            raise ErrorEntrada(f"reporte no es JSON válido: {self.ruta} ({exc})") from exc


def reportes_del_pipeline(carpeta: Path) -> list:
    """Reportes en el orden de importación (no cambiar: SCA antes que imagen)."""
    return [
        Reporte("semgrep", "Semgrep JSON Report", "SAST - Semgrep", carpeta / "semgrep-report.json"),
        Reporte("trivy-sca", "Trivy Scan", "SCA - Trivy (dependencias)", carpeta / "trivy-sca-report.json"),
        Reporte("trivy-image", "Trivy Scan", "Análisis de imagen - Trivy", carpeta / "trivy-image-report.json"),
        Reporte("conftest", "Conftest Scan", "Policy as Code - Conftest", carpeta / "conftest-report.json"),
    ]


class ClienteDefectDojo:
    def __init__(self, config: Configuracion, espera_base: float | None = None):
        self.config = config
        self.espera_base = ESPERA_BASE if espera_base is None else espera_base

    # --- HTTP ------------------------------------------------------------------

    @staticmethod
    def _multipart(campos: dict, archivo: tuple | None = None) -> tuple:
        """Construye un cuerpo multipart/form-data. archivo = (campo, nombre, bytes)."""
        limite = uuid.uuid4().hex
        partes = []
        for nombre, valor in campos.items():
            if valor is None or valor == "":
                continue
            partes.append(
                f'--{limite}\r\nContent-Disposition: form-data; name="{nombre}"\r\n\r\n{valor}\r\n'.encode("utf-8")
            )
        if archivo:
            campo, nombre_archivo, contenido = archivo
            tipo = mimetypes.guess_type(nombre_archivo)[0] or "application/octet-stream"
            cabecera = (
                f'--{limite}\r\nContent-Disposition: form-data; name="{campo}"; filename="{nombre_archivo}"\r\n'
                f"Content-Type: {tipo}\r\n\r\n"
            ).encode("utf-8")
            partes.append(cabecera + contenido + b"\r\n")
        partes.append(f"--{limite}--\r\n".encode("utf-8"))
        return b"".join(partes), f"multipart/form-data; boundary={limite}"

    def _solicitud(self, metodo: str, ruta: str, cuerpo: bytes | None = None, tipo: str | None = None):
        url = f"{self.config.url}{ruta}"
        cabeceras = {"Authorization": f"Token {self.config.token}", "Accept": "application/json"}
        if tipo:
            cabeceras["Content-Type"] = tipo
        ultimo = ""
        for intento in range(1, INTENTOS + 1):
            pedido = urllib.request.Request(url, data=cuerpo, headers=cabeceras, method=metodo)
            try:
                with urllib.request.urlopen(pedido, timeout=TIMEOUT) as resp:
                    texto = resp.read().decode("utf-8", errors="replace")
                    try:
                        datos = json.loads(texto) if texto.strip() else {}
                    except json.JSONDecodeError:
                        raise ErrorApi(f"{metodo} {ruta} -> respuesta no JSON (¿DEFECTDOJO_URL correcta?)") from None
                    if not isinstance(datos, dict):
                        raise ErrorApi(f"{metodo} {ruta} -> se esperaba un objeto JSON y llegó {type(datos).__name__}")
                    return datos
            except urllib.error.HTTPError as exc:
                detalle = exc.read().decode("utf-8", errors="replace").replace(self.config.token, "***")[:500]
                if exc.code >= 500 and intento < INTENTOS:
                    ultimo = f"HTTP {exc.code}"
                else:
                    raise ErrorApi(f"{metodo} {ruta} -> HTTP {exc.code}: {detalle}") from None
            except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
                ultimo = f"error de red: {getattr(exc, 'reason', exc)}"
                if intento == INTENTOS:
                    break
            espera = self.espera_base * (2 ** (intento - 1))
            print(f"Reintento {intento}/{INTENTOS - 1} de {metodo} {ruta} en {espera:.0f} s ({ultimo})")
            time.sleep(espera)
        raise ErrorApi(f"{metodo} {ruta} falló tras {INTENTOS} intentos ({ultimo})")

    def _json(self, metodo: str, ruta: str, datos: dict):
        return self._solicitud(metodo, ruta, json.dumps(datos).encode("utf-8"), "application/json")

    # --- Operaciones -------------------------------------------------------------

    def reimportar(self, reporte: Reporte) -> dict:
        c = self.config
        fin = (dt.date.today() + dt.timedelta(days=365)).isoformat()
        campos = {
            "scan_type": reporte.scan_type,
            "test_title": reporte.test_title,
            "auto_create_context": "true",
            "product_type_name": c.product_type,
            "product_name": c.product,
            "engagement_name": c.engagement,
            "engagement_end_date": fin,
            "close_old_findings": "true",
            "deduplication_execution_mode": "sync",
            "active": "true",
            "verified": "false",
            "minimum_severity": "Info",
            "build_id": c.build_id,
            "commit_hash": c.commit,
            "branch_tag": c.rama,
            "version": c.commit[:7],
            "source_code_management_uri": c.repo_uri,
            "tags": "ci,g10",
        }
        cuerpo, tipo = self._multipart(campos, ("file", reporte.ruta.name, reporte.ruta.read_bytes()))
        return self._solicitud("POST", "/api/v2/reimport-scan/", cuerpo, tipo)

    def importar(self, reporte: Reporte, engagement_id: int) -> dict:
        """Importación inicial (import-scan) de un reporte en un Engagement existente."""
        campos = {
            "scan_type": reporte.scan_type,
            "test_title": reporte.test_title,
            "engagement": engagement_id,
            "active": "true",
            "verified": "false",
            "minimum_severity": "Info",
            "deduplication_execution_mode": "sync",
        }
        cuerpo, tipo = self._multipart(campos, ("file", reporte.ruta.name, reporte.ruta.read_bytes()))
        return self._solicitud("POST", "/api/v2/import-scan/", cuerpo, tipo)

    def actualizar_engagement(self, engagement_id: int) -> None:
        c = self.config
        datos = {
            "build_id": c.build_id,
            "commit_hash": c.commit,
            "branch_tag": c.rama,
            "source_code_management_uri": c.repo_uri,
        }
        self._json("PATCH", f"/api/v2/engagements/{engagement_id}/", {k: v for k, v in datos.items() if v})

    def contar_hallazgos(self, test_id: int) -> dict:
        total = self._solicitud("GET", f"/api/v2/findings/?test={test_id}&limit=1").get("count", 0)
        activos = self._solicitud("GET", f"/api/v2/findings/?test={test_id}&active=true&limit=1").get("count", 0)
        duplicados = self._solicitud("GET", f"/api/v2/findings/?test={test_id}&duplicate=true&limit=1").get("count", 0)
        return {"total": total, "activos": activos, "duplicados": duplicados}

    def adjuntar_archivo(self, engagement_id: int, ruta: Path, titulo: str | None = None) -> dict:
        cuerpo, tipo = self._multipart({"title": titulo or ruta.name}, ("file", ruta.name, ruta.read_bytes()))
        return self._solicitud("POST", f"/api/v2/engagements/{engagement_id}/files/", cuerpo, tipo)

    def buscar_uno(self, recurso: str, **filtros):
        consulta = urllib.parse.urlencode(filtros)
        datos = self._solicitud("GET", f"/api/v2/{recurso}/?{consulta}")
        resultados = datos.get("results") or []
        return resultados[0] if resultados else None

    def asegurar_producto(self, nombre: str | None = None, descripcion: str | None = None) -> int:
        c = self.config
        nombre = nombre or c.product
        tipo = self.buscar_uno("product_types", name=c.product_type)
        if not tipo:
            tipo = self._json("POST", "/api/v2/product_types/", {"name": c.product_type})
        producto = self.buscar_uno("products", name=nombre)
        if not producto:
            producto = self._json(
                "POST",
                "/api/v2/products/",
                {
                    "name": nombre,
                    "prod_type": tipo["id"],
                    "description": descripcion
                    or f"API Spring Boot analizada por el pipeline DevSecOps del Grupo 10. Repositorio: {REPOSITORIO}",
                },
            )
        return producto["id"]


class Importador:
    def __init__(self, cliente: ClienteDefectDojo, reportes: list):
        self.cliente = cliente
        self.reportes = reportes
        self.resultados: list = []
        self.adjuntos: list = []
        self.engagement_id = None

    def ejecutar(self) -> int:
        for reporte in self.reportes:
            reporte.validar()
        for reporte in self.reportes:
            respuesta = self.cliente.reimportar(reporte)
            test_id = respuesta.get("test_id") or respuesta.get("test")
            if not test_id:
                raise ErrorApi(f"reimport-scan de {reporte.test_title} no devolvió el id del Test")
            self.engagement_id = respuesta.get("engagement_id") or self.engagement_id
            conteo = self.cliente.contar_hallazgos(test_id) if test_id else {}
            self.resultados.append(
                {
                    "herramienta": reporte.herramienta,
                    "scan_type": reporte.scan_type,
                    "test_title": reporte.test_title,
                    "test_id": test_id,
                    "engagement_id": respuesta.get("engagement_id"),
                    "product_id": respuesta.get("product_id"),
                    "statistics": respuesta.get("statistics"),
                    "hallazgos": conteo,
                }
            )
            print(f"{reporte.test_title}: Test {test_id} ({reporte.scan_type}) -> {conteo}")
        if self.engagement_id:
            self.cliente.actualizar_engagement(self.engagement_id)
            self.adjuntar_complementos()
        return EXIT_OK

    def adjuntar_complementos(self) -> None:
        """Adjunta al Engagement los reportes JSON sin hallazgos importables (SBOM y gate)."""
        if not self.reportes:
            return
        carpeta = self.reportes[0].ruta.parent
        sufijo = self.cliente.config.build_id or "local"
        for nombre in ADJUNTOS_PIPELINE:
            ruta = carpeta / nombre
            if not ruta.is_file():
                print(f"Aviso: {nombre} no está disponible; no se adjunta")
                continue
            titulo = f"{ruta.stem}-{sufijo}{ruta.suffix}"
            self.cliente.adjuntar_archivo(self.engagement_id, ruta, titulo)
            self.adjuntos.append(titulo)
            print(f"Adjuntado al Engagement: {titulo}")

    def resumen(self) -> dict:
        c = self.cliente.config
        return {
            "defectdojo": c.url,
            "product_type": c.product_type,
            "product": c.product,
            "engagement": c.engagement,
            "engagement_id": self.engagement_id,
            "build_id": c.build_id,
            "commit_hash": c.commit,
            "branch_tag": c.rama,
            "importaciones": self.resultados,
            "adjuntos": self.adjuntos,
        }


def archivos_del_engagement(cliente: ClienteDefectDojo, engagement_id: int) -> list:
    datos = cliente._solicitud("GET", f"/api/v2/engagements/{engagement_id}/files/")
    return datos.get("files") or datos.get("results") or []


def modelo_amenazas(cliente: ClienteDefectDojo, archivos: list) -> dict:
    for ruta in archivos:
        if not ruta.is_file():
            raise ErrorEntrada(f"archivo faltante: {ruta}")
    producto_id = cliente.asegurar_producto()
    engagement = cliente.buscar_uno("engagements", product=producto_id, name=ENGAGEMENT_TM)
    if not engagement:
        hoy = dt.date.today().isoformat()
        engagement = cliente._json(
            "POST",
            "/api/v2/engagements/",
            {
                "name": ENGAGEMENT_TM,
                "product": producto_id,
                "target_start": hoy,
                "target_end": hoy,
                "engagement_type": "Interactive",
                "status": "Completed",
                "threat_model": True,
                "description": (
                    "Modelo de amenazas del trabajo 1 del Grupo 10 (Caso 5, Banca Móvil): DFD con límites de "
                    "confianza y 41 amenazas STRIDE (T01-T41) elaborado con OWASP Threat Dragon 2.6.2. "
                    "Se reutiliza sin cambios."
                ),
            },
        )
    eid = engagement["id"]
    existentes = archivos_del_engagement(cliente, eid)
    titulos = {f.get("title") for f in existentes}
    for ruta in archivos:
        if ruta.name not in titulos:
            cliente.adjuntar_archivo(eid, ruta)
            print(f"Adjuntado: {ruta.name}")
    final = archivos_del_engagement(cliente, eid)
    return {"engagement_id": eid, "product_id": producto_id, "archivos": [f.get("title") for f in final]}


def reportes_de_ejemplo(semgrep: Path, trivy: Path, bom: Path) -> list:
    return [
        Reporte("semgrep", "Semgrep JSON Report", "Ejemplo del docente - Semgrep", semgrep),
        Reporte("trivy", "Trivy Scan", "Ejemplo del docente - Trivy (nginx:latest)", trivy),
        Reporte("cyclonedx", "CycloneDX Scan", "Ejemplo - CycloneDX SBOM del proyecto", bom),
    ]


class VerificacionParsers:
    """Importa reportes de ejemplo en un Product separado del proyecto.

    El Product aparte evita que los hallazgos de nginx:latest se mezclen con las métricas
    y la deduplicación de la API; la deduplicación queda limitada al Engagement.
    """

    def __init__(self, cliente: ClienteDefectDojo, reportes: list):
        self.cliente = cliente
        self.reportes_docente = reportes

    def ejecutar(self) -> dict:
        for reporte in self.reportes_docente:
            reporte.validar()
        producto_id = self.cliente.asegurar_producto(
            PRODUCT_EJEMPLOS,
            "Reportes de ejemplo entregados por el docente y SBOM del proyecto, usados solo para comprobar "
            "la compatibilidad de los parsers. No forman parte de las métricas del proyecto.",
        )
        engagement = self.cliente.buscar_uno("engagements", product=producto_id, name=ENGAGEMENT_PARSERS)
        if not engagement:
            hoy = dt.date.today().isoformat()
            engagement = self.cliente._json(
                "POST",
                "/api/v2/engagements/",
                {
                    "name": ENGAGEMENT_PARSERS,
                    "product": producto_id,
                    "target_start": hoy,
                    "target_end": hoy,
                    "engagement_type": "Interactive",
                    "status": "Completed",
                    "deduplication_on_engagement": True,
                    "description": "Comprobación de los parsers Semgrep JSON Report, Trivy Scan y CycloneDX Scan.",
                },
            )
        eid = engagement["id"]
        tests = []
        for reporte in self.reportes_docente:
            existente = self.cliente.buscar_uno("tests", engagement=eid, title=reporte.test_title)
            if existente:
                test_id = existente["id"]
                print(f"{reporte.test_title}: ya importado (Test {test_id})")
            else:
                respuesta = self.cliente.importar(reporte, eid)
                test_id = respuesta.get("test_id") or respuesta.get("test")
                if not test_id:
                    raise ErrorApi(f"import-scan de {reporte.test_title} no devolvió el id del Test")
            conteo = self.cliente.contar_hallazgos(test_id)
            tests.append(
                {
                    "archivo": reporte.ruta.name,
                    "scan_type": reporte.scan_type,
                    "test_title": reporte.test_title,
                    "test_id": test_id,
                    "hallazgos": conteo,
                }
            )
            print(f"{reporte.test_title}: Test {test_id} ({reporte.scan_type}) -> {conteo}")
        return {"product": PRODUCT_EJEMPLOS, "product_id": producto_id, "engagement": ENGAGEMENT_PARSERS, "engagement_id": eid, "tests": tests}


def escribir_resumen_markdown(resumen: dict, destino) -> None:
    if not destino:
        return
    lineas = [
        "## DefectDojo",
        "",
        f"Product `{resumen['product']}` · Engagement `{resumen['engagement']}` (id {resumen['engagement_id']})",
        "",
        "| Test | Parser | Test id | Hallazgos | Activos | Duplicados |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for r in resumen["importaciones"]:
        h = r.get("hallazgos") or {}
        lineas.append(
            f"| {r['test_title']} | {r['scan_type']} | {r['test_id']} | {h.get('total', '?')} | "
            f"{h.get('activos', '?')} | {h.get('duplicados', '?')} |"
        )
    with open(destino, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lineas) + "\n\n")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Importa los reportes del pipeline en DefectDojo.")
    sub = parser.add_subparsers(dest="comando", required=True)
    p = sub.add_parser("pipeline", help="reimporta los reportes del pipeline")
    p.add_argument("--reports", default="reports", help="carpeta con los reportes JSON")
    p.add_argument("--output", help="JSON de resumen (por defecto reports/defectdojo-<runId>.json)")
    m = sub.add_parser("modelo-amenazas", help="crea el Engagement del modelo de amenazas con adjuntos")
    m.add_argument("archivos", nargs="+", help="archivos a adjuntar (PDF y JSON de Threat Dragon)")
    v = sub.add_parser("verificacion-parsers", help="importa los reportes de ejemplo en un Product aparte")
    v.add_argument("--semgrep", required=True, help="semgrep-report.json de ejemplo")
    v.add_argument("--trivy", required=True, help="trivy-report.json de ejemplo")
    v.add_argument("--bom", required=True, help="bom.json (CycloneDX) del proyecto")
    v.add_argument("--output", help="JSON donde se guarda el resultado")
    args = parser.parse_args(argv)

    try:
        config = Configuracion.desde_entorno()
        cliente = ClienteDefectDojo(config)
        if args.comando == "modelo-amenazas":
            print(json.dumps(modelo_amenazas(cliente, [Path(a) for a in args.archivos]), ensure_ascii=False, indent=2))
            return EXIT_OK
        if args.comando == "verificacion-parsers":
            verificacion = VerificacionParsers(
                cliente, reportes_de_ejemplo(Path(args.semgrep), Path(args.trivy), Path(args.bom))
            )
            resultado = verificacion.ejecutar()
            texto = json.dumps(resultado, ensure_ascii=False, indent=2)
            if args.output:
                Path(args.output).write_text(texto + "\n", encoding="utf-8")
            print(texto)
            return EXIT_OK
        carpeta = Path(getattr(args, "reports", "reports"))
        importador = Importador(cliente, reportes_del_pipeline(carpeta))
        importador.ejecutar()
        salida = Path(getattr(args, "output", None) or carpeta / f"defectdojo-{config.build_id or 'local'}.json")
        salida.write_text(json.dumps(importador.resumen(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"Resumen escrito en {salida}")
        escribir_resumen_markdown(importador.resumen(), os.environ.get("GITHUB_STEP_SUMMARY"))
        return EXIT_OK
    except ErrorEntrada as exc:
        print(f"::error::{exc}")
        return EXIT_ENTRADA
    except ErrorApi as exc:
        print(f"::error::DefectDojo: {exc}")
        return EXIT_API


if __name__ == "__main__":
    sys.exit(main())
