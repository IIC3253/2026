# Instrucciones para probar los tests

### 1. Instalar `pytest`, `pytest-json-report` y `pytest-timeout`
```bash
pip install pytest pytest-json-report pytest-timeout

2. Copiar su pregunta2.py al directorio actual

Si su archivo tiene otro nombre, edite la variable STUDENT_FILE al inicio de
grade-upload.py con el nombre de su archivo.

3. Correr grade.py

Al correr este script podrán ver su puntaje (escala 0 a 2).
python grade-upload.py

4. Ver el detalle de los tests fallados

Para ver un reporte más completo, pueden correr pytest directamente con el
siguiente comando:
python -m pytest test_pregunta2.py --json-report --json-report-file=out.report.json
El detalle de los tests fallados queda en el archivo out.report.json.

5. Detalles de la solución

Pueden comparar su entrega con la solución reference_pregunta2.py.

Si ven alguna inconsistencia con su nota, asegurarse de que están usando Python 3.13.7 como indica el enunciado
