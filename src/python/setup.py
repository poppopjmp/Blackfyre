from setuptools import setup, find_packages

setup(
    name='blackfyre',
    version='1.1.0',
    description='Your package description',
    author='Malachi Jones',
    author_email='malachi.jones@jonescyber-ai.com',
    url='https://github.com/kye4u2/Blackfyre',
    packages=find_packages(include=["blackfyre"]),
    package_data={},
    install_requires=[
        "pyvex==9.2.78",
        "protobuf==4.25.1",
        "numpy==1.26.2",
    ],
)
