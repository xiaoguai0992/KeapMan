FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /
RUN apt update -y
RUN apt install curl wget unzip build-essential vim git -y
RUN apt install -y libssl-dev pkg-config zlib1g-dev
RUN git clone https://github.com/SVF-tools/SVF.git
RUN wget https://github.com/Kitware/CMake/releases/download/v3.29.6/cmake-3.29.6.tar.gz
RUN tar -xvf cmake-3.29.6.tar.gz

WORKDIR cmake-3.29.6
RUN ./bootstrap --parallel=$(nproc)
RUN make -j$(nproc)
RUN make install

WORKDIR /SVF
RUN ./build.sh

RUN echo -e "\e[32m[+] Basic environment configuration\e[0m"

RUN apt-get update && \
    apt-get install -y vim && \
    apt install python3 git -y && \
    apt install qemu qemu-system -y && \
    apt install python3-pip -y && \
    apt install flex bison -y \

RUN echo -e "\e[32m[+] Install other related tools\e[0m"

RUN pip3 install pwntools && \
    apt install gdb -y && \
    git clone https://github.com/pwndbg/pwndbg &&  \
    cd pwndbg && \
    ./setup.sh 

RUN echo -e "\e[32m[+] Clone PANDA and install related dependencies\e[0m"


WORKDIR /
RUN apt install cmake ninja-build rapidjson-dev -y
RUN git clone https://github.com/panda-re/libosi.git

WORKDIR /libosi
RUN mkdir build 

WORKDIR /libosi/build
RUN cmake -GNinja ..
RUN ninja
RUN ninja package 
RUN ls
RUN dpkg -i libosi_.deb


WORKDIR /
RUN git clone https://github.com/panda-re/panda.git 

WORKDIR /panda/
RUN apt install --no-install-recommends $(grep -v '^#' ./panda/dependencies/ubuntu_22.04_base.txt | tr '\n' ' ') -y
RUN apt install --no-install-recommends $(grep -v '^#' ./panda/dependencies/ubuntu_22.04_build.txt | tr '\n' ' ') -y
RUN mkdir -p build && cd build 
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
RUN . ~/.bashrc 
RUN . /root/.cargo/env
RUN apt-get install libcapstone-dev -y 

WORKDIR /panda/build/
RUN python3 -m pip install --user -U pip wheel build "setuptools>=80" "setuptools-scm>=8"
RUN . /root/.cargo/env && ../build.sh x86_64-softmmu
RUN . /root/.cargo/env && ../build.sh --python


WORKDIR /panda/panda/python/core
RUN python3 create_panda_datatypes.py --install
RUN pip install -e .

CMD ["/bin/bash"]

