"""Minimal setup.py for backward compatibility with older pip versions."""
from setuptools import setup, find_packages

setup(
    name="preseal",
    version="0.3.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.9",
    install_requires=[
        "langchain-core>=0.3",
        "typer>=0.12",
        "pydantic>=2.0",
        "pydantic-settings>=2.0",
        "pyyaml>=6.0",
        "rich>=13.0",
    ],
    extras_require={
        "langgraph": ["langgraph>=0.2", "langchain-core>=0.3"],
        "dev": ["pytest>=8.0", "ruff>=0.4"],
    },
    entry_points={
        "console_scripts": [
            "preseal=preseal.cli:app",
        ],
    },
)
