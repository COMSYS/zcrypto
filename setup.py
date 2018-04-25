import os
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))

setup(
  name="schemas.zcrypto",
  version="0.0.1",
  description="ZSchema definitions for zcrypto's JSON output.",
  classifiers=[
    "Programming Language :: Python",
    "Natural Language :: English"
  ],
  author="ZMap Team",
  author_email="zmap-team@umich.edu",
  url="https://github.com/zmap/zcrypto",
  keywords="zmap censys ztag internet-wide scanning",
  packages=["schemas"],
  include_package_data=True,
  zip_safe=False,
  install_requires = [
    "zschema",
  ],
  # package_data={"ztag":["devices/*",]},
)
