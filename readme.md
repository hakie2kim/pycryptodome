## 💬 소개

Hybrid Encryption & Decryption 및 Pay-to-Multi-Signature 이론을 적용한 파이썬 스크립트

## Hybrid Encryption & Decryption

### 개념

![image](https://github.com/user-attachments/assets/11cdc7fa-bdcd-4962-91be-83a3c8b79065)

### 과정 설명

**Hybrid Encryption**

1. 이 폴더 안에는 두 개의 별도 파이썬 파일이 있습니다. 이 두 파일을 실행하기 전에 사용자는 해당 파이썬 파일들이 있는 디렉토리로 이동해야 합니다.

`$ cd [파이썬 파일들이 위치한 디렉토리]`

2. 그런 다음, 현재 디렉토리에 있는 `test11.txt`, `test2.txt`, `test3.txt`라는 이름의 모든 텍스트 파일에 대해 하이브리드 암호화를 실행합니다. 다음 명령어를 입력합니다.

`$ python3 hencryption.py`

`hencryption.py` 파일은 먼저 Alice와 Bob을 위한 두 개의 public 및 private 키 쌍을 생성합니다. Alice가 송신자가 되면 Bob은 수신자가 되거나, 반대로 Bob이 송신자가 되고 Alice가 수신자가 될 수 있습니다. 이 과정 후에, `private_Alice.pem`, `public_Alice.pem`, `private_Bob.pem`, `public_Bob.pem` 파일이 현재 디렉토리에 생성됩니다. 이 단계에서는 `hencryption.py`가 실행될 때마다 이 네 개의 `.pem` 파일이 덮어쓰여집니다.

3. 다음으로, 프로그램은 사용자가 Alice인지 Bob인지 묻고 Alice 또는 Bob을 입력하도록 요구합니다. 사용자가 Alice(송신자)라고 가정하면, 프로그램은 symmetric 키를 Bob의(수신자) 공개 키(RSA)로 암호화합니다. `sym_key_encrypted_with_Bob_pk.bin` 파일이 현재 디렉토리에 생성됩니다. 사용자가 Bob(송신자)인 경우, 프로그램은 대칭 키를 Alice의(수신자) 공개 키로 암호화하여 `sym_key_encrypted_with_Alice_pk.bin` 파일을 만듭니다. 이 단계에서는 `hencryption.py`가 실행될 때마다 이 두 개의 바이너리 파일이 덮어쓰여집니다.

![image](https://github.com/user-attachments/assets/8c792343-8ced-4ff1-9b50-aa4b7a8454a0)

4. 마지막으로, 프로그램은 현재 디렉토리 내의 모든 `.txt` 파일의 내용을 읽고, 대칭 키로 생성된 암호를 사용하여 각 텍스트 파일을 대칭적으로 암호화합니다(AES CBC 모드). 이 과정 후에, `test11.enc`, `test2.enc`, `test3.enc` 파일이 현재 디렉토리에 생성되며 모든 암호화 파일과 동일한 초기 벡터가 함께 생성됩니다.

![image](https://github.com/user-attachments/assets/f3c0c17f-254a-43c7-99eb-48d121912122)

**Hybrid Decryption**

1. 현재 디렉토리 내의 `test11.enc`, `test2.enc`, `test3.enc`라는 이름의 모든 `.enc` 파일을 하이브리드 복호화합니다. 다음 명령어를 입력합니다. 프로그램은 자동으로 모든 `.enc` 파일 이름을 읽어 복호화합니다.

`$ python3 hdecryption.py [하이브리드 암호화에서 사용된 초기 벡터]`

![image](https://github.com/user-attachments/assets/fc5cf921-6e40-466e-95ee-34d94efc5ec2)

2. 하이브리드 복호화 과정과 마찬가지로 프로그램은 먼저 사용자가 Alice인지 Bob인지 묻습니다. Alice가 송신자였다고 가정하면, Bob을 수신자로 입력해야 합니다.

3. 그런 다음, 프로그램은 `private_Bob.pem` 파일을 열어 Bob의(수신자) 비밀 키(RSA)를 사용하여 대칭 키를 복호화합니다. 복호화된 대칭 키와 초기 벡터를 사용하여 암호를 생성하고 AES CBC 모드로 모든 `.enc` 파일을 대칭적으로 복호화합니다. 이로 인해 각 `.enc` 파일에 포함된 내용이 복호화되어 나타납니다. Bob이 송신자이고 Alice가 수신자인 경우에도 과정은 유사합니다.

![image](https://github.com/user-attachments/assets/8297c796-f2e1-4a8f-95d2-921306edfe7e)

## Pay-to-Multi-Signature

### 개념

![image](https://github.com/user-attachments/assets/0f81bf69-f1e4-4a92-acd5-05ab72b3414e)
![image](https://github.com/user-attachments/assets/1200d421-8118-49b8-9c6f-b49f2cf3a2a7)

[참고] https://learnmeabitcoin.com/technical/script/p2ms/

### 과정 설명

![image](https://github.com/user-attachments/assets/0f3b0b85-eb4c-43d4-98bd-c6597eb4d357)

[참고] https://learnmeabitcoin.com/technical/script/p2ms/

1. 리눅스에서 다음 명령어를 사용하여 `create.py`를 실행합니다.

```bash
$ python3 create.py
```

프로그램이 사용자가 두 개의 파라미터를 입력하도록 요청합니다. 이 파라미터는 앞에서 설명한 조건을 만족해야 합니다. 실행 후, 두 개의 텍스트 파일 `scriptPubKey.txt`와 `scriptSig.txt`가 생성됩니다. 그림 1은 이 두 텍스트 파일에 저장된 내용을 보여줍니다. `scriptSig.txt`의 `OP_1`은 더미 값이며, `scriptPubKey.txt`의 `2`와 `4`는 각각 서명과 공개 키의 수를 나타냅니다.

![image](https://github.com/user-attachments/assets/f3baef78-c519-4d03-82f1-cd910d3e9178)
![image](https://github.com/user-attachments/assets/1b2a463d-8dd4-4b94-9464-ed6014289a05)

그림 1. 세 쌍의 `scriptPubKey.txt`와 `scriptSig.txt`가 필요했기 때문에 각 파일 이름에 `_1`이 추가되었습니다. 해당 파일에는 두 개의 서명과 네 개의 공개 키가 포함되어 있습니다.

2. 다음으로, 리눅스에서 다음 명령어를 사용하여 `verify.py`를 실행합니다.

```bash
$ python3 verify.py
```

프로그램은 `scriptPubKey.txt`와 `scriptSig.txt`의 모든 요소를 읽어 스택에 푸시합니다(`OP_1` 더미 값 제외). 모든 요소를 푸시한 후, 현재 파이썬 파일은 각 요소를 팝하여 두 개의 다른 리스트에 저장하고 FILO(후입선출) 원칙을 사용하여 확인합니다. 이제 서명과 공개 키를 확인하여 스크립트를 검증하는 단계가 준비됐습니다. 서명이 유효할 때마다 집계 수가 1씩 증가합니다. 스크립트가 비워지고 서명의 수가 집계와 일치하면 프로그램은 스택에 1을 푸시하고 종료합니다. 그림 2에서 그림 4는 세 가지 유효한 스크립트의 사례를 보여줍니다.

![image](https://github.com/user-attachments/assets/613910bd-9c2d-4840-b2b8-1bc31f1f2112)
![image](https://github.com/user-attachments/assets/b163f15d-407d-4573-bf22-07bbd6388053)
![image](https://github.com/user-attachments/assets/addd2637-1186-4ee2-b115-157f401e2139)

그림 2. `scriptPubKey_1`과 `scriptSig_1` 서명 수(M)는 2이고 공개 키 수(N)는 4입니다. `sig_1`은 `pub_key_1`로, `sig_2`는 `pub_key_3`로 검증되었습니다.

![image](https://github.com/user-attachments/assets/be561400-bad3-4737-ab90-0fb1c09c1f79)
![image](https://github.com/user-attachments/assets/40d049ff-fb64-4d09-b3a0-68f55e99f476)
![image](https://github.com/user-attachments/assets/2329bf8b-4c84-47a9-9168-5cd16d0631f6)

그림 3. `scriptPubKey_2`와 `scriptSig_2` 서명 수(M)는 3이고 공개 키 수(N)는 5입니다. `sig_1`은 `pub_key_1`로, `sig_2`는 `pub_key_2`로, `sig_3`는 `pub_key_4`로 검증되었습니다.

![image](https://github.com/user-attachments/assets/f2763ab0-cb8f-4667-b039-5fa1d4a4cecd)
![image](https://github.com/user-attachments/assets/ae589273-e5dc-43f9-a4c6-e0ce4c25c799)
![image](https://github.com/user-attachments/assets/34c83e1d-9c14-4e0c-bb95-5519434459ba)

그림 4. `scriptPubKey_3`과 `scriptSig_3` 서명 수(M)는 4이고 공개 키 수(N)는 7입니다. `sig_1`은 `pub_key_2`로, `sig_2`는 `pub_key_4`로, `sig_3`는 `pub_key_6`로, `sig_4`는 `pub_key_7`로 검증되었습니다.
