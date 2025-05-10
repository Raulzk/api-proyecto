from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import base64
import tempfile
import os
import pefile
import time

# Inicializar la aplicación Flask
app = Flask(__name__)
CORS(app)  # Habilita CORS para todas las solicitudes

# Cargar el modelo de machine learning
try:
    model = joblib.load('random_forest_model.pkl')
except Exception as e:
    print(f"Error al cargar el modelo: {str(e)}")
    model = None


@app.route('/predict', methods=['POST'])
def predict():
    if model is None:
        return jsonify({"error": "Modelo no cargado correctamente"}), 500

    try:
        data = request.get_json(force=True)
        if 'features' not in data:
            return jsonify({"error": "Falta el campo 'features' en el JSON"}), 400
        prediction = model.predict([data['features']])
        return jsonify({'prediction': prediction.tolist()})
    except Exception as e:
        return jsonify({"error": f"Error en la predicción: {str(e)}"}), 500


@app.route('/extract_features', methods=['POST'])
def extract_features():
    try:
        data = request.json
        # Verificar si el archivo en base64 fue enviado
        if 'file_base64' not in data:
            return jsonify({"error": "No se proporcionó un archivo en base64"}), 400

        # Decodificar el archivo base64
        file_base64 = data['file_base64']
        try:
            file_binary = base64.b64decode(file_base64)
        except base64.binascii.Error:
            return jsonify({"error": "El archivo proporcionado no es un base64 válido"}), 400

        # Guardar el archivo temporalmente
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as temp_file:
            temp_file.write(file_binary)
            temp_file_path = temp_file.name

        try:
            pe = pefile.PE(temp_file_path)
            features = {
                "Machine": int(pe.FILE_HEADER.Machine),
                "DebugSize": int(pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].Size),
                "DebugRVA": int(pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].VirtualAddress),
                "MajorImageVersion": int(pe.OPTIONAL_HEADER.MajorImageVersion),
                "MajorOSVersion": int(pe.OPTIONAL_HEADER.MajorOperatingSystemVersion),
                "ExportRVA": int(pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress),
                "ExportSize": int(pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size),
                "IatVRA": int(pe.OPTIONAL_HEADER.DATA_DIRECTORY[12].VirtualAddress),
                "MajorLinkerVersion": int(pe.OPTIONAL_HEADER.MajorLinkerVersion),
                "MinorLinkerVersion": int(pe.OPTIONAL_HEADER.MinorLinkerVersion),
                "NumberOfSections": int(pe.FILE_HEADER.NumberOfSections),
                "SizeOfStackReserve": int(pe.OPTIONAL_HEADER.SizeOfStackReserve),
                "DllCharacteristics": int(pe.OPTIONAL_HEADER.DllCharacteristics),
                "ResourceSize": int(pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size),
                "BitcoinAddresses": 0  # Placeholder
            }
            pe.close()  # Cierra explícitamente el archivo
        except Exception as e:
            return jsonify({"error": f"Error al procesar el archivo: {str(e)}"}), 500
        finally:
            # Esperar y reintentar eliminar el archivo
            for _ in range(5):  # Intentar 5 veces
                try:
                    os.remove(temp_file_path)
                    break
                except PermissionError:
                    time.sleep(1)  # Esperar 1 segundo antes de reintentar
            else:
                print(f"No se pudo eliminar el archivo temporal: {temp_file_path}")

        return jsonify(features)
    except Exception as e:
        return jsonify({"error": f"Error en la extracción de características: {str(e)}"}), 500


if __name__ == '__main__':
    # Obtener el puerto de la variable de entorno PORT, o usar 5000 por defecto
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
