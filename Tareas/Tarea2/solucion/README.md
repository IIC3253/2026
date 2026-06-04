# Instrucciones para probar los tests

### 1. Instalar `pytest` y `pytest-json-report`
```bash
pip install pytest pytest-json-report
```

### 2. Copiar su `feistel.py` al directorio actual

### 3. Correr `grade.py`
Al correr este script podrán ver su nota.
```bash
python grade.py
```

### 4. Ver el detalle de los tests fallados
Pueden encontrar el detalle de los tests fallados en el archivo `out.report.json`.

Para ver un reporte más completo, pueden correr pytest directamente con el siguiente comando:
```bash
python -m pytest test_feistel.py --json-report --json-report-file=out.report.json
```

### 5. Detalles de la solución
Pueden comparar su entrega con la solución `reference_feistel.py`.

### Si ven alguna inconsistencia con su nota, asegurarse de que están usando Python 3.13.7 como indica el enunciado