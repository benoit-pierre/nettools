


import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

with open("requirements.txt") as fh:
    dependencies = [l.strip() for l in fh.read().replace("\r\n", "\n").\
        split("\n") if len(l.strip()) > 0]

setuptools.setup(
    name="nettools",
    version="0.1",
    author="Jonas Thiem",
    author_email="jonas@thiem.email",
    description="A pure python, self-contained package " +
        "of net/web helpers for TCP, WebDAV, HTML/XML, ...",
    packages=["nettools"],
    install_requires=dependencies,
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/JonasT/nettools",
    data_files = [("", ["LICENSE.md"])],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
)


