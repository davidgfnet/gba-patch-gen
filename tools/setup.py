import setuptools

VERSION = "0.2.0"

setuptools.setup(
    name="patchtool",
    url="https://github.com/davidgfnet/gba-patch-gen",
    author="davidgfnet",
    keywords="GBA patch tool library",
    description="A tool to generate GBA patches for Supercard",
    license="GPL",
    classifiers=[
        "Operating System :: OS Independent",
        "Topic :: Software Development",
        "Programming Language :: Python :: 3",
    ],
    python_requires=">=3.0",
    version=VERSION,
    packages=setuptools.find_packages(),
)

