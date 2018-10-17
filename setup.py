


import setuptools

with open("README.md", "r") as fh:
    with open("LICENSE.md", "r") as f2:
        long_description = fh.read().rstrip() + "\n\n" + f2.read()

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
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
)


