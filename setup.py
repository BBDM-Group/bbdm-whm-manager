import setuptools

setuptools.setup(
   name='WhamPy',
   version='0.0.1',
   author='Dmitry Minin',
   author_email='dmitry.m@bbdmgroup.com',
   packages=['whampy'],
   scripts=[],
   url='http://pypi.python.org/pypi/whampy/',
   license='LICENSE.txt',
   description='WHM Api interface',
   long_description=open('README.txt').read(),
   install_requires=[
      "certifi==2022.9.24",
      "charset-normalizer==2.1.1",
      "colorama==0.4.5",
      "idna==3.4",
      "requests==2.28.1",
      "urllib3==1.26.12"
   ],
)