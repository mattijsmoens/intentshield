from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="intentshield",
    version="1.1.1",
    author="Mattijs Moens",
    description="Pre-execution intent verification for AI agents",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mattijsmoens/intentshield",
    license="BSL-1.1",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    keywords="ai safety llm agent security intent verification",
)
