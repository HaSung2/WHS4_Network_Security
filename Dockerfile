# Ubuntu 최신 버전을 기반으로 생성
FROM ubuntu:latest

# 비대화형 설치를 위한 설정
ENV DEBIAN_FRONTEND=noninteractive

# 패키지 업데이트 및 필요한 도구 설치
RUN apt-get update && apt-get install -y \
    git \
    net-tools \
    python3 \
    wireshark \
    python3-pip \
    gedit \
    scapy \
    libpcap-dev \
    && apt-get clean

# 작업 디렉토리 설정
WORKDIR /workspace

# 저장소 클론
RUN git clone https://github.com/pwnhyo/network_security_codes.git

# 컨테이너 실행 시 기본적으로 쉘(bash)을 실행
CMD ["/bin/bash"]
