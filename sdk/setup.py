import os
from setuptools import setup, find_packages

this_directory = os.path.abspath(os.path.dirname(__file__))
try:
    with open(os.path.join(this_directory, "README.md"), encoding="utf-8") as f:
        long_description = f.read()
except FileNotFoundError:
    long_description = "Python client for the Sentinel Secure Ingestion Platform"

setup(
    name="sentinel-py",
    version="0.1.0",
    description="Official Python client for the Sentinel Secure Ingestion Platform",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Preet Kulkarni",
    url="https://github.com/preetkulkarni/sentinel-secure-ingestion",
    packages=find_packages(),
    install_requires=[
        "requests>=2.31.0",
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
)