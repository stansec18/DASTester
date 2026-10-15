from pathlib import Path
from setuptools import setup, find_packages

here = Path(__file__).parent
version = {}
exec((here / "dastester" / "__version__.py").read_text(), version)

long_description = (here / "README.md").read_text(encoding="utf-8")
requirements = [
    line.strip()
    for line in (here / "requirements.txt").read_text().splitlines()
    if line.strip() and not line.startswith("#")
]

setup(
    name="dastester",
    version=version["__version__"],
    description="A DAST scanner with OWASP Top 10 and STRIDE reporting.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="DASTester contributors",
    license="MIT",
    packages=find_packages(),
    include_package_data=True,
    package_data={"dastester": ["reporting/templates/*.html", "data/*.yaml"]},
    install_requires=requirements,
    python_requires=">=3.9",
    entry_points={
        "console_scripts": [
            "dastester=dastester.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
    ],
)
