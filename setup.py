from setuptools import setup, find_packages

setup(
    name="jsstrike",
    version="1.0.0",
    description="JavaScript static analysis CLI for authorized security testing & bug bounty recon",
    author="JS Strike Contributors",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.28.0",
        "beautifulsoup4>=4.11.0",
    ],
    entry_points={
        "console_scripts": [
            "jsstrike=jsstrike.main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
    ],
)

