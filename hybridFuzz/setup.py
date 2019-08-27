from setuptools import setup
# from sys import version_info


setup(
    name='hybridFuzz_iot',
    version='0.0.1',
    packages=['hybridFuzz',
              ],
    install_requires=[
        'capstone>=3.0.4',
        'keystone-engine',
    ],
    description='Hybrid fuzzing for arbitrary ARM firmware'
)
