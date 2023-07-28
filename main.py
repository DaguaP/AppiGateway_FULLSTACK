from flask import Flask
from flask import jsonify
from flask import request
from flask_cors import CORS
import json
from waitress import serve
import datetime
import requests
import re
from flask_jwt_extended import create_access_token, verify_jwt_in_request
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager



app = Flask(__name__)
cors = CORS(app)


app.config["JWT_SECRET_KEY"] = "super-secret" # Cambiar por el que se conveniente
jwt = JWTManager(app)


@app.route("/login", methods=["POST"])
def create_token():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-security"] + '/usuarios/validar'
    response = requests.post(url, json=data, headers=headers)
    if response.status_code == 200:
        user = response.json()
        expires = datetime.timedelta(seconds=60 * 60 * 24)
        access_token = create_access_token(identity=user, expires_delta=expires)
        return jsonify({"token": access_token, "user_id": user["_id"]})
    else:
        return jsonify({"msg": "Bad username or password"}), 401



# Funcion que se ejecutará siempre de primero antes de que la consulta llegue a la ruta solicitada
@app.before_request
def before_request_callback():
    endPoint = limpiarURL(request.path)
    excludedRoutes = ["/login"]
    if excludedRoutes.__contains__(request.path):
        pass
    elif verify_jwt_in_request():
        usuario = get_jwt_identity()
        if usuario["rol"] is not None:
            tienePersmiso = validarPermiso(endPoint, request.method, usuario["rol"]["_id"])
            if not tienePersmiso:
                return jsonify({"message": "Permission denied"}), 401
        else:
            return jsonify({"message": "Permission denied"}), 401


def limpiarURL(url):
    partes = url.split("/")
    for laParte in partes:
        if re.search('\\d', laParte):
            url = url.replace(laParte, "?")
    return url


def validarPermiso(endPoint, metodo, idRol):
    url = dataConfig["url-backend-security"] + "/permisos-roles/validar-permiso/rol/" + str(idRol)
    tienePermiso = False
    headers = {"Content-Type": "application/json; charset=utf-8"}
    body = {
        "url": endPoint,
        "metodo": metodo
    }
    response = requests.get(url, json=body, headers=headers)
    try:
        data = response.json()
        if ("_id" in data):
            tienePermiso = True
    except:
        pass
    return tienePermiso


############################Redireccionamiento personas########################################
@app.route("/personas", methods=['GET'])
def getPersonas():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventario"] + '/personas'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/personas", methods=['POST'])
def crearPersona():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventario"] + '/personas'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/personas/<string:id>", methods=['GET'])
def getPersona(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventario"] + '/personas/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/personas/<string:id>", methods=['PUT'])
def modificarPersona(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventario"] + '/personas/' + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/personas/<string:id>", methods=['DELETE'])
def eliminarPersona(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventario"] + '/personas/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)



############################Redireccionamiento proveedor########################################
@app.route("/proveedores", methods=['GET'])
def getProveedores():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventario"] + '/proveedores'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

#pendiente por añadir una ruta si es necesaria de proveedor ver productos

@app.route("/proveedores", methods=['POST'])
def crearProveedores():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventario"] + '/proveedores'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/proveedores/<string:id>", methods=['GET'])
def getProveedor(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventario"] + '/proveedores/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/proveedores/<string:id>", methods=['PUT'])
def modificarProveedore(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventario"] + '/proveedores/' + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/proveedores/<string:id>", methods=['DELETE'])
def eliminarProveedor(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventario"] + '/proveedores/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)




############################Redireccionamiento productos########################################
@app.route("/productos", methods=['GET'])
def getProductos():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventario"] + '/productos'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)



@app.route("/productos", methods=['POST'])
def crearProducto():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventario"] + '/productos'
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/productos/<string:id>", methods=['GET'])
def getProducto(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventario"] + '/productos/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/productos/<string:id>", methods=['PUT'])
def modificarProducto(id):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventario"] + '/productos/' + id
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)


@app.route("/productos/<string:id>", methods=['DELETE'])
def eliminarProducto(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventario"] + '/productos/' + id
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)

### Pendiente por resolver --> no deja asignar proveedorProducto
@app.route("/productos/<string:id>/proveedor/<string:id_proveedor>", methods=['PUT'])
def asignarProveedorAProducto(id, id_proveedor):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventario"] + '/productos/' + id + '/proveedor/' + id_proveedor
    response = requests.put(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)



############################Redireccionamiento inventario########################################
@app.route("/inventarios", methods=['GET'])
def getInventarios():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventario"] + '/inventarios'
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)

### Pendiente por corregir --> al eliminar un inventario y volverlo a buscar se cae el sistema
@app.route("/inventarios/<string:id>", methods=['GET'])
def getInventario(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventario"] + '/inventarios/' + id
    response = requests.get(url, headers=headers)
    json = response.json()
    return jsonify(json)



@app.route("/inventarios/persona/<string:id_persona>/producto/<string:id_producto>", methods=['POST'])
def crearInventario(id_persona, id_producto):
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventario"] + '/inventarios/persona/' + id_persona + '/producto/' + id_producto
    response = requests.post(url, headers=headers, json=data)
    json = response.json()
    return jsonify(json)



#pendiente por corregir errores --> no funciona la actualizacion pero la ruta al parecer esta bien
@app.route("/inventarios/<string:id_inventario>/persona/<string:id_persona>/producto/<string:id_producto>", methods=['PUT'])
def modificarInventario(id_inventario, id_persona, id_producto):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig[
              "url-backend-inventario"] + '/inventarios/' + id_inventario + '/persona/' + id_persona + '/producto/'+ id_producto
    response = requests.put(url, headers=headers)
    json = response.json()
    return jsonify(json)


@app.route("/inventarios/<string:id_inventario>", methods=['DELETE'])
def eliminarInventario(id_inventario):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-inventario"] + '/inventarios/' + id_inventario
    response = requests.delete(url, headers=headers)
    json = response.json()
    return jsonify(json)




@app.route("/", methods=['GET'])
def test():
    json = {}
    json["message"] = "Server running ..."
    return jsonify(json)

def loadFileConfig():
    with open('config.json') as f:
        data = json.load(f)
    return data

if __name__ == '__main__':
    dataConfig = loadFileConfig()
    print("Server running : " + "http://" + dataConfig["url-backend"] + ":" + str(dataConfig["port"]))
    serve(app, host=dataConfig["url-backend"], port=dataConfig["port"])

