from setuptools import setup

package_name = 'ros2_security'

setup(
    name=package_name,
    version='0.1.0',
    packages=[package_name],
    data_files=[
        ('share/ament_index/resource_index/packages',
            ['resource/' + package_name]),
        ('share/' + package_name, ['package.xml']),
    ],
    install_requires=['setuptools'],
    zip_safe=True,
    maintainer='Fredi Romo',
    maintainer_email='fredi@radix.com.mx',
    description='Thin authentication/authorization/encryption middleware layer '
                'for ROS2 nodes (no SROS2).',
    license='Apache-2.0',
    tests_require=['pytest'],
    entry_points={
        'console_scripts': [
            'secure_echo = ros2_security.secure_echo:main',
            'legacy_relay = ros2_security.legacy_relay:main',
        ],
    },
)
