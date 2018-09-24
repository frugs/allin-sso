import setuptools

VERSION = "0.0.6"

setuptools.setup(
    name="allinsso",
    packages=setuptools.find_packages(),
    package_data={"allinsso": ["templates/*", "static/styles/*", "static/images/*"]},
    version=VERSION,
    description="Single Sign-on app for All Inspiration Apps",
    author="Hugo Wainwright",
    author_email="wainwrighthugo@gmail.com",
    url="https://github.com/frugs/allin-sso",
    keywords=["sc2", "all-inspiration"],
    classifiers=[],
    install_requires=["Flask-OAuthlib", "flask", "google-cloud-datastore"],
)
