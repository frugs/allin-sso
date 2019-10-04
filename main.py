from allinsso import app


def main():
    app.run(host="localhost", port=5000, debug=True, ssl_context='adhoc')


if __name__ == "__main__":
    main()
