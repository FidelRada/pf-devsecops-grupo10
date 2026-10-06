# Modelo de amenazas – Caso 5: Banca Móvil (Grupo 10)

Esta carpeta contiene, **sin modificaciones**, el modelado de amenazas que el Grupo 10 (Bautista Condori Anderzon, Grichukin Méndez Richard, Rada Rojas Andrés Fidel y Vargas Ríos Bebi) presentó en el primer trabajo del módulo. El proyecto final lo reutiliza tal como se entregó: no se rehace. Los ajustes que introduce la implementación final están en [`ajustes.md`](ajustes.md).

| Archivo | Contenido |
|---|---|
| `Grupo10_Caso5_BancaMovil.json` | Modelo de OWASP Threat Dragon 2.6.2: diagrama de flujo de datos (DFD) con límites de confianza y las 41 amenazas (T01–T41) clasificadas con STRIDE. Se abre con Threat Dragon. |
| `Reporte_ThreatDragon_Caso5_Grupo10.pdf` | Reporte exportado desde Threat Dragon: diagrama y detalle de cada amenaza con su mitigación. |
| `Informe_ThreatModeling_Caso5_Grupo10.docx` | Informe del trabajo 1 (formato SOE). |

La presentación de la exposición se entregó junto con el trabajo 1 y no se incluye en este repositorio.

## Resumen

- **Caso:** aplicación de banca móvil (Caso 5).
- **Metodología:** STRIDE sobre un DFD. Se usó Threat Dragon porque el equipo trabaja en Linux y Microsoft Threat Modeling Tool solo funciona en Windows; la consigna admite esa alternativa.
- **Total de amenazas:** 41.

| Categoría STRIDE | Amenazas |
|---|---:|
| Spoofing (suplantación) | 6 |
| Tampering (manipulación) | 9 |
| Repudiation (repudio) | 3 |
| Information disclosure (divulgación de información) | 14 |
| Denial of service (denegación de servicio) | 5 |
| Elevation of privilege (elevación de privilegios) | 4 |
| **Total** | **41** |

El total se puede comprobar con:

```bash
python3 -c "import json; d=json.load(open('Grupo10_Caso5_BancaMovil.json')); \
print(sum(len((c.get('data') or {}).get('threats', [])) for g in d['detail']['diagrams'] for c in g['cells']))"
```

## Integridad de la copia

| Archivo | SHA-256 |
|---|---|
| `Grupo10_Caso5_BancaMovil.json` | `7b4389fe1da5e4f6a71c476cdabd7927bfd7ad9b3bc321ce95d147ed48e04aae` |
| `Informe_ThreatModeling_Caso5_Grupo10.docx` | `cb2a5c8afe3f7662be3d51f3d834fd0ea7d292c4d704b5a62cd76b19cf7db5c2` |
| `Reporte_ThreatDragon_Caso5_Grupo10.pdf` | `efc699aa28e79c03504edd5ee0fbb0b5bb6d56d29e88624abdb2f66e8fb26103` |

## Relación con el pipeline

El modelo describe el sistema del Caso 5; la aplicación que analiza el pipeline es la de este repositorio (API Spring Boot deliberadamente vulnerable). Las amenazas de inyección, divulgación de información, componentes vulnerables y elevación de privilegios del modelo tienen su contraparte en los hallazgos de SAST, SCA, imagen y políticas del pipeline, que se gestionan en DefectDojo. En DefectDojo, el Product `spring-boot-webapi-secure` tiene además un Engagement "Modelado de amenazas – Caso 5 Banca Móvil" con el PDF y el JSON de esta carpeta adjuntos.
