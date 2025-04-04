from flask import Flask, request, jsonify
import json

CONFIG_FILE="config.json"
app = Flask(__name__)

@app.route("/update-whitelist" , methods=["POST"])
def updateWHitelist():
    try:
        data = request.get_json()
        with open(CONFIG_FILE, "a") as f:
            json.dump(data, f, indent=4)
        return jsonify({"message":"whitelist updated"}),200
    except Exception as e:
        return jsonify({"error" : str(e), status : 500 }) ,500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
