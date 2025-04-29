from setuptools import setup, find_packages

setup(
    name="blackfyre",
    version="0.2.0",
    packages=find_packages(),
    install_requires=[
        "click>=7.0",
        "protobuf>=3.0.0",
        "matplotlib>=3.3.0",
        "networkx>=2.5.0",
        "pyvex>=9.0.0",
        "archinfo>=9.0.0",
        "numpy>=1.19.0",
        "requests>=2.25.0",  # For LLM API calls
        "scikit-learn>=0.24.0",  # For ML components
        # Add other dependencies as needed
    ],
    entry_points={
        'console_scripts': [
            'blackfyre=blackfyre.cli:cli',
        ],
    },
    author="Blackfyre Team",
    author_email="blackfyre@example.com",
    description="A platform for standardizing and streamlining binary analysis",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/jonescyber-ai/Blackfyre",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)
