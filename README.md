# Pipeline DevSecOps CI/CD con DefectDojo – Grupo 10

Proyecto final del Módulo 5 (Seguridad en DevOps), UAGRM – FICCT. Docente: MSc. José Pablo Villazón Valdez.

**Grupo 10:** Bautista Condori Anderzon, Grichukin Méndez Richard, Rada Rojas Andrés Fidel y Vargas Ríos Bebi.

Este repositorio parte de [`pablovillazon/spring-boot-webapi-secure`](https://github.com/pablovillazon/spring-boot-webapi-secure), con su historial, y le agrega:

- un pipeline de **CI en GitHub Actions** que compila, prueba y ejecuta cada control de seguridad como un step propio, con todos los reportes en JSON;
- un **quality gate** que decide con el contenido de los reportes;
- un **CD local** por dos vías: un runner self-hosted con Docker Compose y un script de despliegue manual desde los artifacts;
- la **importación de los reportes** en una instancia propia de **DefectDojo**;
- el **modelo de amenazas** del trabajo 1 y sus ajustes en [`docs/threat-model/`](docs/threat-model/README.md).

> **Advertencia:** la aplicación es deliberadamente vulnerable. Ejecutarla solo en `localhost` o en una red de laboratorio aislada.

## Cómo funciona el pipeline

El workflow [`.github/workflows/devsecops.yml`](.github/workflows/devsecops.yml) se ejecuta en cada `push` a `main`, en cada pull request hacia `main` y a mano (`workflow_dispatch`). Tiene tres jobs:

```text
ci (GitHub, ubuntu-latest)
 ├─ Compilar y probar ............................ mvn -B clean verify
 ├─ Pruebas de scripts ........................... python3 -m unittest
 ├─ SAST - Semgrep ............................... reports/semgrep-report.json
 ├─ SCA - SBOM CycloneDX ......................... reports/bom.json
 ├─ SCA - Trivy (dependencias) ................... reports/trivy-sca-report.json
 ├─ Construir imagen del proyecto ................ pf-g10-webapi:<commit>
 ├─ Análisis de imagen - Trivy ................... reports/trivy-image-report.json
 ├─ Policy as Code - Conftest (pruebas de la política)
 ├─ Policy as Code - Conftest (Dockerfile) ....... reports/conftest-report.json
 ├─ Publicar reportes JSON ....................... artifact reportes-devsecops (aunque algo falle)
 ├─ Quality gate ................................. reports/gate.json
 ├─ Publicar resultado del gate .................. artifact gate
 ├─ Exportar imagen aprobada ..................... imagen-webapi.tar.gz (solo si el gate aprueba)
 └─ Publicar imagen aprobada ..................... artifact imagen-webapi
defectdojo (runner local; push a main o manual sobre main; corre aunque el gate falle)
 └─ Importar en DefectDojo ....................... reimport-scan de los 4 reportes + adjuntos
cd-local (runner local; solo si ci y defectdojo terminan bien)
 ├─ Cargar imagen y comprobar que es la escaneada
 ├─ Desplegar con Docker Compose ................. 127.0.0.1:8085
 └─ Smoke test ................................... GET /actuator/health
```

En los pull requests solo corre `ci`: los jobs locales aparecen como *skipped*. No hay pruebas dinámicas (DAST): la única petición a la aplicación es la comprobación de salud tras el despliegue.

Las acciones están fijadas por SHA y las imágenes de las herramientas por versión y digest. El workflow tiene `permissions: contents: read`.

### Controles, herramientas y reportes JSON

| Control | Herramienta | Parámetro JSON | Reporte | Parser en DefectDojo |
|---|---|---|---|---|
| SAST | Semgrep 1.178.0 (`p/java`, `p/owasp-top-ten` y `.semgrep.yml`) | `--json --output reports/semgrep-report.json` | `semgrep-report.json` | Semgrep JSON Report |
| SCA | CycloneDX Maven 2.9.3 + Trivy 0.74.0 (`trivy sbom`) | `outputFormat=json` (pom) y `--format json --output reports/trivy-sca-report.json` | `bom.json`, `trivy-sca-report.json` | CycloneDX Scan (el SBOM no trae vulnerabilidades) y Trivy Scan |
| Análisis de imagen | Trivy 0.74.0 sobre `pf-g10-webapi:<commit>` | `--format json --output reports/trivy-image-report.json` | `trivy-image-report.json` | Trivy Scan |
| Policy as Code | Conftest v0.71.0 + `policy/dockerfile.rego` | `--output json`, redirigido a `reports/conftest-report.json` | `conftest-report.json` | Conftest Scan |
| Quality gate | `scripts/gate.py` | JSON propio | `gate.json` | Sin parser: se adjunta al Engagement |

Ningún análisis usa `--exit-code` ni `--error`: los escáneres siempre generan su reporte y la decisión la toma el gate.

### Quality gate

[`scripts/gate.py`](scripts/gate.py) lee los cuatro reportes y termina con:

- **1 (bloqueado)** si hay un resultado de Semgrep `ERROR` (o `CRITICAL`/`HIGH`), una vulnerabilidad de Trivy `HIGH`/`CRITICAL` **con versión corregida** (dependencias o imagen) o una violación `deny` de Conftest;
- **2 (fail-closed)** si un reporte falta, está vacío, no es JSON o UTF-8, tiene una estructura inesperada, Trivy no analizó ningún paquete (`Results` vacío) o Semgrep informó errores técnicos;
- **0 (aprobado)** en otro caso. Los `WARNING`, las vulnerabilidades sin corrección y los avisos `warn` se informan, pero no bloquean.

El resultado queda en `gate.json` (`decision`, `codigo`, `por_control`, `bloqueantes` y `errores`) y en una tabla del resumen del run. Por cada control que bloquea, el gate emite una anotación de error con su nombre, visible en la página del run. Conftest devuelve 1 tanto con violaciones como ante un error de sintaxis Rego, así que [`scripts/validar_conftest.py`](scripts/validar_conftest.py) revisa el código, stderr y la estructura del JSON y convierte un error técnico en código 2.

### Políticas del Dockerfile

[`policy/dockerfile.rego`](policy/dockerfile.rego) (Rego v1) **bloquea**: etapa final sin `USER` o con root; `FROM` sin tag o con `latest`; imagen final sin digest `@sha256:`; imagen final que no es JRE; falta de `HEALTHCHECK`; `ADD` de una URL remota; secretos en `ENV`/`ARG`. **Avisa**: `HEALTHCHECK` con `curl` en una imagen Alpine (no lo trae) y `COPY --from` sin `--chown`. Las pruebas de la política están en `policy/dockerfile_test.rego` y se ejecutan en el pipeline:

```bash
docker run --rm -v "$PWD:/project" -w /project openpolicyagent/conftest:v0.71.0 verify --policy policy
```

## Descargar los reportes de un run

Los reportes se publican como artifacts del run (30 días de retención). El artifact `reportes-devsecops` se sube **antes** del gate y aunque falle un step anterior, así que se conserva también cuando el pipeline queda en rojo.

```bash
gh run list -R FidelRada/pf-devsecops-grupo10 --workflow devsecops.yml
gh run download <run-id> -R FidelRada/pf-devsecops-grupo10 -n reportes-devsecops -D reportes
gh run download <run-id> -R FidelRada/pf-devsecops-grupo10 -n gate -D reportes
```

También se descargan desde la página del run, en la sección *Artifacts*.

## Despliegue local (CD)

La versión desplegada es la imagen `pf-g10-webapi:<commit>` que construyó y escaneó el job `ci`. Solo se exporta como artifact (`imagen-webapi`) si el gate aprueba, y antes de desplegarla se comprueba que su ID sea el `Metadata.ImageID` del reporte de Trivy del mismo run: se despliega exactamente la imagen analizada. [`deploy/compose.yml`](deploy/compose.yml) la levanta solo en `127.0.0.1:8085`, con usuario no root, sistema de archivos de solo lectura, `cap_drop: ALL`, `no-new-privileges` y `pull_policy: never` (la imagen nunca se descarga de un registro).

### Vía automática: runner self-hosted

Con el runner encendido, cada push a `main` que aprueba el gate ejecuta el job `cd-local`: descarga los artifacts, carga la imagen con `docker load`, compara el ID, ejecuta `docker compose up -d --wait` y comprueba `/actuator/health`. El resumen del run muestra la imagen desplegada.

### Vía manual: desde los artifacts

[`scripts/desplegar_local.sh`](scripts/desplegar_local.sh) hace lo mismo a mano y funciona con el runner apagado:

```bash
scripts/desplegar_local.sh <run-id>
```

1. Comprueba con `gh run view` que el run sea un `push` o un `workflow_dispatch` sobre `main` y que haya terminado en `success`.
2. Descarga `imagen-webapi` y `reportes-devsecops` con `gh run download`.
3. Carga la imagen (`gunzip -c … | docker load`) y exige que la etiqueta cargada sea `pf-g10-webapi:<sha>` y coincida con el `ArtifactName` del reporte de imagen.
4. Compara el ID de la imagen cargada con `Metadata.ImageID`; si no coincide, se detiene sin desplegar.
5. Ejecuta `docker compose -f deploy/compose.yml -p pf-g10-webapi up -d --wait`.
6. Comprueba `http://127.0.0.1:8085/actuator/health`.

`scripts/desplegar_local.sh --solo-verificar <run-id>` hace los pasos 2 a 4 sin desplegar ni exigir que el run sea de `main` (por ejemplo, para revisar el artifact de un pull request). Para detener la aplicación:

```bash
docker compose -f deploy/compose.yml -p pf-g10-webapi down
```

Las variables de la aplicación van en un archivo fuera del repositorio cuya ruta se indica en `APP_ENV_FILE` (permisos 600). Como Compose interpreta `$` en ese archivo, los hashes bcrypt se escriben entre comillas simples:

```bash
LAB_ADMIN_PASSWORD_HASH='$2a$10$...'
LAB_USER_PASSWORD_HASH='$2a$10$...'
LAB_EXTERNAL_API_KEY='...'
```

Si un hash falta, ese usuario no se crea y la aplicación arranca igual (solo quedan los endpoints públicos).

## DefectDojo local

Instancia propia de DefectDojo 3.3.300 con Docker Compose, publicada solo en `127.0.0.1:8080`. Basta con una carpeta mínima:

1. Descargar el `docker-compose.yml` del tag y el `README.md` de `docker/extra_settings/` (es un *bind mount* del compose):

   ```bash
   mkdir -p defectdojo/docker/extra_settings && cd defectdojo
   curl -fsSLo docker-compose.yml https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/3.3.300/docker-compose.yml
   curl -fsSLo docker/extra_settings/README.md https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/3.3.300/docker/extra_settings/README.md
   ```

2. Crear `.env.local` (permisos 600, **nunca** en Git) con valores aleatorios: `DJANGO_VERSION=3.3.300`, `NGINX_VERSION=3.3.300`, `DD_SECRET_KEY`, `DD_CREDENTIAL_AES_256_KEY`, `DD_ADMIN_PASSWORD`, `DD_DATABASE_PASSWORD` y un `DD_DATABASE_URL` coherente. Un valor se genera con `python3 -c 'import secrets; print(secrets.token_urlsafe(32))'`.
3. Crear `docker-compose.override.yml` para escuchar solo en local y fijar la contraseña del administrador:

   ```yaml
   name: dojo-g10
   services:
     nginx:
       ports: !override
         - target: 8080
           published: 8080
           host_ip: 127.0.0.1
     initializer:
       environment:
         DD_ADMIN_PASSWORD: ${DD_ADMIN_PASSWORD}
   ```

4. Levantarla sin construir imágenes y esperar a que el `initializer` termine con código 0:

   ```bash
   docker compose --env-file .env.local up -d --no-build
   docker compose --env-file .env.local ps -a
   ```

5. Entrar en http://127.0.0.1:8080 con `admin` y la contraseña de `.env.local`. La API key se obtiene con `POST /api/v2/api-token-auth/` y se guarda en `.env.local` sin mostrarla.
6. Activar la deduplicación, que viene desactivada en una instalación nueva: *Configuration → System Settings → Deduplicate findings*, o `PATCH /api/v2/system_settings/1/` con `{"enable_deduplication": true}`.

### Organización

- Product Type **Proyecto Final G10** → Product **spring-boot-webapi-secure** (con el enlace a este repositorio).
  - Engagement **Pipeline CI/CD (main)** con un Test por control: *SAST - Semgrep*, *SCA - Trivy (dependencias)*, *Análisis de imagen - Trivy* y *Policy as Code - Conftest*. Cada push a `main` los reimporta: los hallazgos corregidos pasan a *Mitigated*. El Engagement guarda el run, el commit y la rama, y lleva adjuntos `bom.json` y `gate.json` de cada run.
  - Engagement **Modelado de amenazas – Caso 5 Banca Móvil** con el PDF y el JSON del modelo adjuntos.
- Product **Reportes de ejemplo del docente** → Engagement **Verificación de parsers**: los reportes de ejemplo de Semgrep y Trivy y el `bom.json` del proyecto, para comprobar que los parsers los aceptan sin mezclarlos con las métricas de la API.

SCA se importa antes que la imagen: DefectDojo marca como *Duplicate* en el Test de imagen las CVE de librerías Java que ya reportó el SBOM, de modo que cada vulnerabilidad se gestiona una sola vez.

Carga manual de los Engagements que no dependen del pipeline:

```bash
export DEFECTDOJO_URL=http://127.0.0.1:8080
export DEFECTDOJO_API_KEY="$(grep '^DD_API_KEY=' defectdojo/.env.local | cut -d= -f2-)"
python3 scripts/importar_defectdojo.py modelo-amenazas \
  docs/threat-model/Reporte_ThreatDragon_Caso5_Grupo10.pdf docs/threat-model/Grupo10_Caso5_BancaMovil.json
python3 scripts/importar_defectdojo.py verificacion-parsers \
  --semgrep <semgrep-report.json de ejemplo> --trivy <trivy-report.json de ejemplo> --bom reportes/bom.json
```

Los reportes también pueden cargarse a mano desde la interfaz (*Import Scan Results*), eligiendo el parser de la tabla de controles.

## Runner self-hosted

Los jobs `defectdojo` y `cd-local` corren en la PC del grupo con un runner de GitHub Actions instalado con el usuario normal (sin `sudo` ni servicio del sistema):

```bash
mkdir runner && cd runner
curl -fsSLO https://github.com/actions/runner/releases/download/v2.337.0/actions-runner-linux-x64-2.337.0.tar.gz
# comprobar el SHA-256 publicado en la página del release
tar xzf actions-runner-linux-x64-2.337.0.tar.gz
./config.sh --url https://github.com/FidelRada/pf-devsecops-grupo10 --token <token de registro> \
  --name g10pf-pc --labels g10pf-local --work /home/<usuario>/g10pf-runner-work --unattended --disableupdate
chmod 600 .credentials .credentials_rsaparams .runner
./run.sh   # solo mientras se ejecuta el pipeline; detenerlo al terminar
```

La carpeta de trabajo (`--work`) debe estar en una ruta **sin espacios**: el runner pasa a `bash` la ruta del script de cada step sin comillas y un espacio la corta.

Seguridad del runner (el repositorio es público):

- el repositorio exige aprobación para los workflows de **todos** los colaboradores externos y nunca se aprueba un run de un fork;
- los jobs locales solo corren en `push` o `workflow_dispatch` sobre `main` de este repositorio;
- el secreto `DEFECTDOJO_API_KEY` existe solo en el entorno `cd-local`, que únicamente acepta la rama `main`;
- `./run.sh` se lanza solo durante la ejecución del pipeline (no como servicio);
- el `GITHUB_TOKEN` es de solo lectura, el checkout no guarda credenciales y DefectDojo y la aplicación escuchan solo en `127.0.0.1`;
- los archivos de registro del runner tienen permisos 600.

**Riesgo residual:** el usuario que ejecuta el runner pertenece al grupo `docker`, porque los jobs usan Docker. Eso equivale a privilegios de root en la PC: un workflow malicioso que llegara a ejecutarse en el runner podría tomar el control del equipo. Por eso los controles anteriores impiden que código de terceros llegue al runner. Al terminar el proyecto, el runner se elimina con `./config.sh remove`.

El secreto lo crea el dueño del repositorio, leyendo el valor desde `.env.local` sin mostrarlo y sin salto de línea final:

```bash
grep '^DD_API_KEY=' defectdojo/.env.local | cut -d= -f2- | tr -d '\n' \
  | gh secret set DEFECTDOJO_API_KEY --env cd-local --repo FidelRada/pf-devsecops-grupo10
```

## Reproducir los análisis en local

```bash
mkdir -p reports
mvn -B clean verify
python3 -m unittest discover -s tests -v

docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD:/src" -w /src semgrep/semgrep:1.178.0 \
  semgrep scan --metrics=off --config p/java --config p/owasp-top-ten --config .semgrep.yml \
  --json --output reports/semgrep-report.json src/main/java

mvn -B -DskipTests org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeAggregateBom && cp target/bom.json reports/bom.json
docker run --rm -v "$PWD:/w" -v trivy-cache:/root/.cache/trivy -w /w aquasec/trivy:0.74.0 \
  sbom --format json --output reports/trivy-sca-report.json reports/bom.json

docker build -t pf-g10-webapi:local .
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$PWD:/w" -v trivy-cache:/root/.cache/trivy -w /w \
  aquasec/trivy:0.74.0 image --image-src docker --format json --output reports/trivy-image-report.json pf-g10-webapi:local

rc=0; docker run --rm -v "$PWD:/project" -w /project openpolicyagent/conftest:v0.71.0 \
  test Dockerfile --parser dockerfile --policy policy --output json > reports/conftest-report.json 2> conftest.err || rc=$?
python3 scripts/validar_conftest.py reports/conftest-report.json conftest.err "$rc"

python3 scripts/gate.py --reports reports --output reports/gate.json
```

## Aplicación

API Spring Boot 4.0 (Java 21, Maven, H2 en memoria). El proyecto base es deliberadamente vulnerable; las correcciones aplicadas se describen en el pull request de remediación.

```bash
mvn clean verify
mvn spring-boot:run   # http://localhost:8080
```

| Endpoint | Acceso |
|---|---|
| `GET /api/products/search?name=Laptop` | público |
| `GET /actuator/health` | público |
| `POST /api/auth/login` | público (valida usuario y contraseña) |
| `POST /api/comments/preview` | usuario autenticado, con token CSRF |
| `GET /api/admin/users/{id}` y el resto de `/actuator/**` | rol `ADMIN` |

La autenticación es HTTP Basic contra los usuarios `admin` (rol `ADMIN`) y `ana` (rol `USER`), cuyos hashes bcrypt llegan por las variables `LAB_ADMIN_PASSWORD_HASH` y `LAB_USER_PASSWORD_HASH`. Un hash se genera, por ejemplo, con `htpasswd -nbBC 10 "" '<contraseña>' | cut -d: -f2`.
