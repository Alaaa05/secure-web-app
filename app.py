from flask import Flask, render_template

app = Flask(__name__)

# temporary key for now, Task 4 will replace it with a proper secret key
app.secret_key = "dev-key"


@app.route("/")
def home():
    # just a test page to check the app runs
    return render_template("index.html")


if __name__ == "__main__":
    # debug=True shows errors in the browser while we're building
    app.run(debug=True)