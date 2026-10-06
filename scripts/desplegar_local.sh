#!/usr/bin/env bash
# Despliegue local manual de la versión que construyó y aprobó el pipeline.
#
# Uso:
#   scripts/desplegar_local.sh <run-id>                 despliega la imagen del run
#   scripts/desplegar_local.sh --solo-verificar <run-id>
#       descarga, carga y compara el ID de la imagen sin desplegar ni exigir que el
#       run sea de main (sirve para comprobar el artifact de un pull request)
#   scripts/desplegar_local.sh --verificar-archivos <imagen.tar.gz> <trivy-image-report.json>
#       solo carga y compara, con archivos ya descargados
#
# Pasos del despliegue:
#   1. El run debe ser un push o un workflow_dispatch sobre main y haber terminado en success.
#   2. gh run download de los artifacts imagen-webapi y reportes-devsecops.
#   3. docker load; la etiqueta cargada debe ser pf-g10-webapi:<sha> y coincidir con el
#      ArtifactName del reporte de Trivy.
#   4. El ID de la imagen cargada debe ser igual a Metadata.ImageID del reporte: así se
#      despliega exactamente la imagen que se escaneó.
#   5. docker compose up con esa etiqueta (pull_policy: never), usando el deploy/compose.yml
#      del mismo commit del run (descargado de GitHub), no el de la copia local.
#   6. Comprobación de /actuator/health.
#
# Requisitos: gh autenticado, Docker con Compose y python3. Para que la aplicación tenga
# usuarios, exportar antes APP_ENV_FILE con la ruta del archivo de variables (fuera del
# repositorio); sin él arranca igual, pero solo con los endpoints públicos.

set -euo pipefail

REPO="FidelRada/pf-devsecops-grupo10"
IMAGEN="pf-g10-webapi"
PROYECTO="pf-g10-webapi"
URL_SALUD="http://127.0.0.1:8085/actuator/health"

uso() {
  sed -n '4,10p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 2
}

error() {
  echo "ERROR: $*" >&2
  exit 1
}

campo_json() {
  # campo_json <archivo> <clave> [<subclave>...]: imprime un valor del JSON.
  python3 - "$@" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as fh:
    valor = json.load(fh)
for clave in sys.argv[2:]:
    valor = valor[clave]
print(valor)
PY
}

verificar_origen() {
  local id="$1" datos evento rama conclusion
  datos="$(gh run view "$id" -R "$REPO" --json event,headBranch,conclusion,headSha \
    --jq '[.event, .headBranch, .conclusion, .headSha] | @tsv')"
  IFS=$'\t' read -r evento rama conclusion COMMIT_RUN <<< "$datos"
  echo "Run $id: evento=$evento, rama=$rama, conclusión=$conclusion, commit=$COMMIT_RUN"
  [ "$conclusion" = "success" ] || error "el run $id no terminó en success ($conclusion): no hay imagen aprobada"
  case "$evento" in
    push | workflow_dispatch) ;;
    *) error "el run $id es de un evento '$evento': solo se despliegan runs de push o workflow_dispatch" ;;
  esac
  [ "$rama" = "main" ] || error "el run $id es de la rama '$rama': solo se despliegan runs de main"
}

# Carga la imagen y comprueba que es la escaneada. Deja la etiqueta en CARGADA.
verificar_imagen() {
  local tarball="$1" reporte="$2" nombre_reporte id_cargada id_escaneada
  [ -f "$tarball" ] || error "no existe $tarball"
  [ -f "$reporte" ] || error "no existe $reporte"

  CARGADA="$(gunzip -c "$tarball" | docker load | sed -n 's/^Loaded image: //p' | tail -n 1)"
  echo "Etiqueta cargada:          $CARGADA"
  [[ "$CARGADA" =~ ^${IMAGEN}:[0-9a-f]{40}$ ]] || error "la etiqueta cargada no tiene la forma ${IMAGEN}:<sha>"

  nombre_reporte="$(campo_json "$reporte" ArtifactName)"
  echo "ArtifactName del reporte:  $nombre_reporte"
  [ "$CARGADA" = "$nombre_reporte" ] || error "la imagen cargada no es la que analizó el reporte de Trivy"

  id_cargada="$(docker image inspect "$CARGADA" --format '{{.Id}}')"
  id_escaneada="$(campo_json "$reporte" Metadata ImageID)"
  echo "ID de la imagen cargada:   $id_cargada"
  echo "ID de la imagen escaneada: $id_escaneada"
  [ "$id_cargada" = "$id_escaneada" ] || error "el ID de la imagen no coincide con el escaneado: no se despliega"
  echo "Comprobación correcta: la imagen cargada es la que escaneó Trivy."
}

modo="desplegar"
case "${1:-}" in
  --solo-verificar) modo="verificar"; shift ;;
  --verificar-archivos) modo="archivos"; shift ;;
  -h | --help | "") uso ;;
esac

if [ "$modo" = "archivos" ]; then
  [ $# -eq 2 ] || uso
  verificar_imagen "$1" "$2"
  exit 0
fi

[ $# -eq 1 ] || uso
RUN_ID="$1"
[[ "$RUN_ID" =~ ^[0-9]+$ ]] || error "el run-id debe ser numérico"

if [ "$modo" = "desplegar" ]; then
  verificar_origen "$RUN_ID"
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "Descargando artifacts del run $RUN_ID..."
gh run download "$RUN_ID" -R "$REPO" -n imagen-webapi -n reportes-devsecops -D "$TMP"

verificar_imagen "$TMP/imagen-webapi/imagen-webapi.tar.gz" "$TMP/reportes-devsecops/trivy-image-report.json"

if [ "$modo" = "verificar" ]; then
  echo "Modo --solo-verificar: no se despliega."
  exit 0
fi

# Se usa el compose.yml del commit del run, no el de la copia local del repositorio.
gh api -H "Accept: application/vnd.github.raw" "repos/$REPO/contents/deploy/compose.yml?ref=$COMMIT_RUN" > "$TMP/compose.yml"
echo "deploy/compose.yml tomado del commit $COMMIT_RUN"
if [ -z "${APP_ENV_FILE:-}" ]; then
  echo "Aviso: APP_ENV_FILE no está definido; la aplicación arrancará sin usuarios (solo endpoints públicos)."
fi

IMAGE_TAG="${CARGADA#*:}" docker compose -f "$TMP/compose.yml" -p "$PROYECTO" up -d --wait --wait-timeout 120

respuesta="$(curl -fsS --retry 10 --retry-delay 5 --retry-all-errors "$URL_SALUD")"
echo "$URL_SALUD -> $respuesta"
grep -q '"status":"UP"' <<< "$respuesta" || error "la aplicación no respondió UP"
echo "Desplegado $CARGADA en http://127.0.0.1:8085"
