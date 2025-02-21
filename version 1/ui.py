from flask import Flask

app = Flask(__name__)

@app.route("/", METHODS=["GET"])
@app.route("/index.html", METHODS=["GET"])
def homeMenu():
    try:
        with open("UI/index.html", 'r') as file:
            data = file.read()
            file.close()
        return data, 200
    except Exception as e:
        


app.run(
    host = "0.0.0.0",
    port = 8080,
    debug = True
    )