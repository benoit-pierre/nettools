
'''
nettools - Copyright 2018-2019 python nettools team, see AUTHORS.md

This software is provided 'as-is', without any express or implied
warranty. In no event will the authors be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

1. The origin of this software must not be misrepresented; you must not
   claim that you wrote the original software. If you use this software
   in a product, an acknowledgment in the product documentation would be
   appreciated but is not required.
2. Altered source versions must be plainly marked as such, and must not be
   misrepresented as being the original software.
3. This notice may not be removed or altered from any source distribution.
'''

import sys
if int(sys.version.split(".")[0]) < 3:
    raise RuntimeError("python2 is not supported")

import setuptools
from setuptools import setup, Extension, Command
from setuptools.command.build_ext import build_ext
import os

class cythonize_build_ext_hook(build_ext):
    def run(self):
        from Cython.Build import cythonize
        for root, dirs, files in os.walk(os.path.abspath(
                os.path.join(
                os.path.dirname(__file__), "nettools"))):
            for f in files:
                if not f.endswith(".pyx"):
                    continue
                full_path = os.path.join(root, f)
                c_path = full_path.rpartition(".")[0] + ".c"
                if os.path.exists(c_path):
                    os.remove(c_path)
                cythonize(full_path,
                    include_path=[os.path.join(os.path.dirname(
                    os.path.abspath(__file__)), "src")],
                    compiler_directives={
                        'always_allow_keywords': True,
                        'boundscheck': True,
                        'language_level': 3,
                    }
                )
        super().run()


with open("README.md", "r") as fh:
    with open("LICENSE.md", "r") as f2:
        long_description = fh.read().rstrip() + "\n\n" + f2.read()

with open("requirements.txt") as fh:
    dependencies = [l.strip() for l in fh.read().replace("\r\n", "\n").\
        split("\n") if len(l.strip()) > 0]


def extensions():
    base = os.path.normpath(os.path.abspath(
            os.path.join(
            os.path.dirname(__file__), "nettools")))
    result = []
    for root, dirs, files in os.walk(base):
        for f in files:
            if not f.endswith(".pyx"):
                continue
            full_path = os.path.normpath(os.path.abspath(
                os.path.join(root, f)))
            assert(full_path.startswith(base))
            module = "nettools." + full_path[len(base):].\
                replace(os.path.sep, ".").replace("/", ".").\
                replace("..", ".")
            if module.endswith(".pyx"):
                module = module[:-len(".pyx")]
            if module.startswith("."):
                module = module[1:]
            if module.endswith("."):
                module = module[:1]
            c_relpath = full_path[len(base):].rpartition(".")[0] + ".c"
            if c_relpath.startswith(os.path.sep):
                c_relpath = c_relpath[1:]
            c_relpath = os.path.join('nettools', c_relpath)
            result.append(Extension(module, [c_relpath]))
    return result

setuptools.setup(
    name="nettools",
    version="0.1",
    cmdclass={
        "build_ext": cythonize_build_ext_hook
    },
    author="Jonas Thiem",
    author_email="jonas@thiem.email",
    ext_modules=extensions(),
    description="A pure python, self-contained package " +
        "of net/web helpers for TCP, WebDAV, HTML/XML, ...",
    packages=["nettools"],
    package_data={"nettools": [
        "*.pxd",
    ]},
    install_requires=dependencies,
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/JonasT/nettools",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
)


