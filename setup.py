from setuptools import setup, find_packages


def readme():
    with open('README.md') as f:
        return f.read()


setup(
    name='threshold-crypto',
    version='0.3.0',
    keywords='elgamal threshold decryption',
    description='ElGamal-based threshold decryption',
    long_description=readme(),
    url='https://github.com/tompetersen/threshold-crypto',
    author='Tom Petersen, SVS, Universität Hamburg',
    packages=find_packages(),
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Topic :: Security :: Cryptography',
    ],
    install_requires=[
        'pynacl',
    ],
)