# CEMA Correlation System

Framework demostrador para integrar eventos procedentes de fuentes ciber y electromagnéticas en un modelo común de conciencia situacional orientado a la misión. El sistema normaliza eventos heterogéneos, los clasifica mediante catálogos de técnicas, aplica reglas de correlación, reconstruye cadenas de ataque, predice posibles continuaciones y recomienda contramedidas defensivas.

El sistema está pensado como una capa de razonamiento *cross-domain*: no sustituye a herramientas de monitorización ciber o EW, sino que consume sus eventos ya detectados y los relaciona para ayudar al operador a interpretar campañas adversarias coordinadas.

## Funcionalidades principales

- Normalización de eventos ciber y electromagnéticos en un modelo común (`ClassifiedEvent`).
- Clasificación de eventos ciber mediante MITRE ATT&CK Enterprise.
- Clasificación de eventos electromagnéticos mediante una matriz EW propia basada en doctrina de guerra electrónica.
- Correlación de eventos mediante cinco reglas:
  - progresión de *kill chain*;
  - correspondencia doctrinal EW–MITRE;
  - convergencia de activo;
  - proximidad geográfica;
  - artefactos compartidos.
- Extracción de cadenas de ataque como componentes conexas del grafo de correlaciones.
- Predicción de posibles continuaciones de cadena mediante LLM.
- Recomendación de contramedidas mediante MITRE D3FEND y matriz propia de defensas EW.
- Interfaz Streamlit con tres vistas: `Dashboard`, `Incidents` y `Events`.

## Estructura del proyecto

```text
.
├── config.json                         # Configuración global del sistema
├── requirements.txt                    # Dependencias Python
├── .env.example                        # Ejemplo de configuración de endpoints LLM
├── knowledge/                          # Catálogos y matrices del sistema
│   ├── mitre_techniques.json
│   ├── ew_techniques.json
│   ├── tactics_order.json
│   ├── ew_mitre_mapping.json
│   ├── mitre_techniques_countermeasures.json
│   └── ew_techniques_countermeasures.json
├── scenarios/                          # Bases de datos y eventos de escenarios
│   ├── tfm_system.db
│   ├── scenario_gnss_5g.db
│   ├── scenario_gnss_5g.events.json
│   ├── scenario_adsb_classified.db
│   └── scenario_adsb_classified.events.json
├── src/
│   ├── pipeline.py                     # Orquestador principal del sistema
│   ├── schemas.py                      # Modelos Pydantic
│   ├── storage.py                      # Persistencia SQLite
│   ├── modules/
│   │   ├── classifier_base.py
│   │   ├── cyber_classifier.py
│   │   ├── ew_classifier.py
│   │   ├── engine.py
│   │   ├── rules.py
│   │   ├── chains.py
│   │   ├── predictor.py
│   │   ├── countermeasures.py
│   │   └── llm_client.py
│   └── ui/
│       ├── app.py                      # Entrada de Streamlit
│       ├── app_state.py                # Estado compartido de Streamlit
│       ├── ui_data.py
│       ├── ui_plots.py
│       ├── ui_theme.py
│       └── views/
│           ├── dashboard.py
│           ├── incidents.py
│           └── events.py
└── tests/                              # Scripts de prueba y validación
    ├── example_pipeline.py
    ├── example_engine.py
    ├── example_storage.py
    ├── example_classify.py
    ├── example_predictor.py
    ├── example_mmsi_attack.py
    ├── scenario_gnss_5g_denial.py
    ├── scenario_adsb_prediction.py
    ├── validation_sensitivity.py
    ├── validation_weights_threshold_cross.py
    └── validation_full_3d.py
```

## Requisitos

Se necesita servidor LLM con API OpenAI-compatible (vLLM u OpenAI).

Se recomienda usar Python 3.11 o superior. El proyecto utiliza, entre otras, las siguientes librerías:

- `pydantic`
- `langchain-openai`
- `python-dotenv`
- `streamlit`
- `plotly`
- `networkx`
- `matplotlib`

Las dependencias completas están recogidas en `requirements.txt`.

## Instalación

Desde la raíz del proyecto:

```powershell
py -m venv .venv
```

Activar el entorno virtual en PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Si PowerShell bloquea la activación por la política de ejecución de scripts, se puede habilitar solo para la terminal actual:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

Instalar las dependencias:

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Configuración del LLM

El sistema está preparado para usar modelos servidos mediante una API compatible con OpenAI, por ejemplo vLLM.

Crear un fichero `.env` a partir del ejemplo:

```powershell
copy .env.example .env
```

El fichero `.env.example` contiene las variables esperadas:

```text
GPT_OSS_URL=http://<LLM_SERVER_HOST>:<PORT>/v1
GPT_OSS_URL_B=http://<LLM_SERVER_HOST>:<PORT>/v1
GEMMA_URL=http://<LLM_SERVER_HOST>:<PORT>/v1

GPT_OSS_MODEL=<model-name>
GEMMA_MODEL=<model-name>
```

Sustituir `<LLM_SERVER_HOST>` por el host o IP del servidor donde esté desplegado el modelo. No es necesario documentar ni subir direcciones IP reales al repositorio. Si los endpoints o nombres de modelo cambian, deben modificarse en `.env`.


## Ejecución de la interfaz

Para lanzar la aplicación ejecutar:

```powershell
streamlit run src/ui/app.py
```

La interfaz incluye tres vistas principales:

- `Dashboard`: visión agregada de eventos, dominios y cadenas activas.
- `Incidents`: detalle de cadenas de ataque, grafo de correlaciones, predicciones y contramedidas.
- `Events`: registro completo de eventos clasificados y detalle individual de cada alerta.

En el menú lateral se pueden modificar filtros globales como dominios visibles, umbral mínimo de `strength`, ventana temporal y número mínimo de eventos por cadena.

## Uso de bases de datos de escenarios

La base de datos que usa la aplicación se define en `config.json`, dentro de:

```json
"paths": {
  "db": "scenarios/tfm_system.db"
}
```

Para cargar otra base de datos ya generada, modificar ese campo. Por ejemplo:

```json
"db": "scenarios/scenario_gnss_5g.db"
```

O bien:

```json
"db": "scenarios/scenario_adsb_classified.db"
```

Tras cambiar la base de datos, reiniciar Streamlit para que el pipeline se vuelva a cargar con la nueva configuración.

## Scripts de prueba

Los scripts deben ejecutarse desde la raíz del proyecto.

Pruebas que no dependen del LLM:

```powershell
python tests/example_storage.py
python tests/example_engine.py
python tests/example_pipeline.py
python tests/example_chains.py
python tests/example_countermeasures.py
```

Pruebas que sí llaman al LLM:

```powershell
python tests/example_classify.py
python tests/example_predictor.py
python tests/example_mmsi_attack.py
python tests/scenario_gnss_5g_denial.py
python tests/scenario_adsb_prediction.py
```

## Scripts de validación

Los scripts de validación para el análisis de parámetros del motor de correlación reutilizan bases de datos ya pobladas y no reclasifican eventos si no es necesario.

```powershell
python tests/validation_sensitivity.py
python tests/validation_weights_threshold_cross.py
python tests/validation_full_3d.py
```

Estos scripts generan salidas como CSV y figuras PNG con los resultados del análisis de sensibilidad de parámetros. Para que funcionen correctamente, deben existir previamente las bases de datos de los escenarios correspondientes dentro de `scenarios/`.

## Configuración del motor

Los parámetros principales del sistema están centralizados en `config.json`:

```json
"correlation": {
  "global_tau_t": 600.0
}
```

```json
"rule_weights": {
  "kill_chain": 0.30,
  "cross_domain": 0.20,
  "asset_convergence": 0.10,
  "geo_proximity": 0.10,
  "shared_artifact": 0.30
}
```

El umbral mínimo de `strength` no se fija en `config.json`, sino desde la interfaz de usuario mediante el slider `Min pair strength`.

## Flujo general del sistema

El flujo de procesado es el siguiente:

1. Se recibe un evento crudo ciber o EW.
2. El evento se valida mediante modelos Pydantic.
3. El clasificador asigna una o varias técnicas al evento.
4. El evento clasificado se guarda en SQLite.
5. El motor recupera eventos cercanos en ventana temporal.
6. Se aplican las reglas de correlación compatibles con cada par.
7. Las evidencias se agregan en una fuerza de correlación (`strength`).
8. El extractor construye un grafo y obtiene cadenas de ataque.
9. La interfaz permite inspeccionar cadenas, lanzar predicciones y consultar contramedidas.


## Notas de desarrollo

- Si se añaden nuevas reglas de correlación, deben registrarse en `RULE_CONSTRUCTORS` dentro de `src/pipeline.py` y añadirse también a `config.json`.
- Si se añaden nuevas técnicas, deben actualizarse los catálogos de `knowledge/` y revisar las matrices de correspondencia y contramedidas.
