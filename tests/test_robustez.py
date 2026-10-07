"""Entradas anómalas: los scripts terminan con un error controlado, sin traza ni secretos."""

import io
import json
import sys
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))

import gate  # noqa: E402
import importar_defectdojo as imp  # noqa: E402
import validar_conftest as vc  # noqa: E402

TOKEN = "token-de-prueba-robustez-0123456789"


class RespuestaFalsa(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def cliente():
    config = imp.Configuracion.desde_entorno({"DEFECTDOJO_URL": "http://127.0.0.1:1", "DEFECTDOJO_API_KEY": TOKEN})
    return imp.ClienteDefectDojo(config, espera_base=0)


class GateRobustezTest(unittest.TestCase):
    def test_json_con_anidamiento_excesivo_es_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            ruta = Path(d) / "semgrep-report.json"
            ruta.write_text("[" * 200000 + "]" * 200000, encoding="utf-8")
            with self.assertRaises(gate.ReporteInvalido):
                gate.leer_json(ruta)


class ValidadorRobustezTest(unittest.TestCase):
    def test_reporte_no_utf8_termina_con_2(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "r.json").write_bytes(b"\xff\xfe[]")
            (Path(d) / "e.txt").write_bytes(b"")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(vc.main([str(Path(d) / "r.json"), str(Path(d) / "e.txt"), "0"]), 2)

    def test_stderr_no_utf8_no_rompe_la_validacion(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "r.json").write_text(json.dumps([{"filename": "Dockerfile", "successes": 1}]), encoding="utf-8")
            (Path(d) / "e.txt").write_bytes(b"\xff aviso")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(vc.main([str(Path(d) / "r.json"), str(Path(d) / "e.txt"), "0"]), 0)


class ImportadorRobustezTest(unittest.TestCase):
    def test_url_sin_esquema_es_error_de_entrada(self):
        with self.assertRaises(imp.ErrorEntrada):
            imp.Configuracion.desde_entorno({"DEFECTDOJO_URL": "127.0.0.1:8080", "DEFECTDOJO_API_KEY": TOKEN})

    def test_respuesta_json_que_no_es_objeto(self):
        for cuerpo in (b"[]", b'"ok"', b"3"):
            with self.subTest(cuerpo=cuerpo), mock.patch("urllib.request.urlopen", return_value=RespuestaFalsa(cuerpo)):
                with self.assertRaises(imp.ErrorApi):
                    cliente()._solicitud("GET", "/api/v2/tests/")

    def test_cuerpo_de_error_con_el_token_se_enmascara(self):
        error = urllib.error.HTTPError("http://x", 400, "Bad Request", {}, io.BytesIO(f"Token {TOKEN}".encode()))
        with mock.patch("urllib.request.urlopen", side_effect=error):
            with self.assertRaises(imp.ErrorApi) as ctx:
                cliente()._solicitud("POST", "/api/v2/reimport-scan/")
        self.assertNotIn(TOKEN, str(ctx.exception))
        self.assertIn("***", str(ctx.exception))

    def test_sin_subcomando_no_importa(self):
        with redirect_stdout(io.StringIO()), mock.patch("sys.stderr", io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                imp.main([])
        self.assertEqual(ctx.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
