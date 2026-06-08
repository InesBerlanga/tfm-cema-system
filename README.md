# Clasificador Ciber–EW

Módulos de clasificación de eventos ciber (MITRE ATT&CK) y de Guerra Electrónica
(matriz EW propia) basados en LLMs locales servidos vía API OpenAI-compatible.

## Estructura

```
.
├── schemas.py              # Modelos Pydantic: eventos crudos, clasificados, asignaciones
├── llm_client.py           # Fábrica de clientes ChatOpenAI hacia tus endpoints
├── classifier_base.py      # Lógica común: prompt, parseo, validación de IDs
├── cyber_classifier.py     # Clasificador MITRE ATT&CK (subclase)
├── ew_classifier.py        # Clasificador EW (subclase)
├── knowledge/
│   ├── mitre_techniques.json    # Catálogo MITRE (muestra; sustituir por el real)
│   └── ew_techniques.json       # Tu matriz EW (muestra; sustituir)
├── example_classify.py     # Ejemplo de uso end-to-end
├── requirements.txt
└── .env.example
```

## Setup en VSCode

```bash
python -m venv .venv
source .venv/bin/activate          # Linux/Mac
# .venv\Scripts\activate            # Windows
pip install -r requirements.txt
cp .env.example .env                # ajusta URLs si tus puertos cambian
```

Selecciona el intérprete `.venv` en VSCode (`Ctrl+Shift+P` → "Python: Select
Interpreter").

## Uso rápido

```bash
python example_classify.py
```

## Decisiones de diseño

- **Sin entrenamiento, solo prompt + catálogo**. El LLM ve el catálogo completo en
  el system prompt y devuelve IDs de ese catálogo. Cualquier ID que no exista se
  descarta (anti-alucinación).
- **Temperature baja (0.1)** para reducir variabilidad. Para defender el TFM
  conviene que el clasificador sea lo más reproducible posible dado que es un LLM.
- **Confidence y reasoning** por técnica devueltos por el LLM. Aunque la
  confidence de un LLM no es calibrada, sirve como señal para ponderar
  correlaciones posteriores.
- **Validación dura de IDs**: se filtran las técnicas que el LLM se invente.
- **Reintento simple** al fallar el parseo del JSON.
