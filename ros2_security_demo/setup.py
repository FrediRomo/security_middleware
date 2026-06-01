import os
from glob import glob

from setuptools import setup

package_name = 'ros2_security_demo'

setup(
    name=package_name,
    version='0.1.0',
    packages=[package_name],
    data_files=[
        ('share/ament_index/resource_index/packages',
            ['resource/' + package_name]),
        ('share/' + package_name, ['package.xml']),
        (os.path.join('share', package_name, 'launch'),
            glob('launch/*.py')),
    ],
    install_requires=['setuptools'],
    zip_safe=True,
    maintainer='Fredi Romo',
    maintainer_email='fredi@radix.com.mx',
    description='Demo publisher and subscriber for testing ros2_security combinations.',
    license='Apache-2.0',
    entry_points={
        'console_scripts': [
            'demo_publisher         = ros2_security_demo.demo_publisher:main',
            'demo_subscriber        = ros2_security_demo.demo_subscriber:main',
            'demo_legacy_publisher  = ros2_security_demo.demo_legacy_publisher:main',
            'demo_relay             = ros2_security_demo.demo_relay:main',
        ],
    },
)
