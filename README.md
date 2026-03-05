# Volatility3-GUI

Volatility 3(`vol.py`)를 GUI로 실행하기 위한 도구입니다.

## 사용 방법

### 1) 사전 조건

- Python 3.10 이상
- Volatility 3 폴더(`vol.py` 포함)

### 2) 중요 실행 규칙

`volgui.py`와 `Volatility3-GUI-1.0.0.exe`는 모두 `vol.py`와 같은 폴더에 두고 실행해야 합니다.

예시(소스 실행):

```text
volatility3/
  vol.py
  volgui.py
```

예시(EXE 실행):

```text
volatility3/
  vol.py
  Volatility3-GUI-1.0.0.exe
```

다른 폴더에서 실행하면 `vol.py not found` 오류가 발생할 수 있습니다.

### 3) 설치

```bash
pip install -r requirements.txt
```

### 4) 실행

소스 실행:

```bash
python volgui.py
```

EXE 실행:

- `Volatility3-GUI-1.0.0.exe` 더블클릭

### 5) GUI 사용 절차

1. `Memory File`에서 덤프 파일 선택
2. 왼쪽 플러그인 목록에서 플러그인 선택
3. 필요한 옵션 입력
4. 모드 선택
- `CLI`: 텍스트 출력 중심
- `Analysis`: 테이블 + 실시간 Raw 패널
5. `Run` 클릭
6. 상태 배지 확인
- `Stage 1/3: Before`
- `Stage 2/3: Running`
- `Stage 3/3: Done`

### 6) 결과 확인

실행 결과는 아래 경로에 저장됩니다.

```text
volgui_output/<timestamp>_<plugin>/
```

주요 파일:

- `command.txt`
- `stdout.txt`
- `stderr.txt`
- `run_meta.json`
- `result.json`
- `result.csv`
- `result.txt`

덤프형 플러그인의 산출물도 동일 output 경로에 저장됩니다.

### 7) 개선 사항 연락

dlwodnr59@gmail.com으로 연락 주시면 최대한 빨리 확인 후 수정 하겠습니다.

## 라이선스

- 본 저장소의 핵심 라이선스 문서는 `LICENSE`입니다.
- Volatility 3는 VSL(v1.0)을 사용합니다.
- PyQt5, PyInstaller 등 서드파티 고지는 `THIRD_PARTY_NOTICES.md`를 확인하십시오.

주의:

- 라이선스 적용 범위와 의무는 배포 방식(소스/바이너리/내부/상용)에 따라 달라질 수 있습니다.
- 본 문서는 법률 자문이 아니며, 최종 배포 전 법무 검토를 권장합니다.
