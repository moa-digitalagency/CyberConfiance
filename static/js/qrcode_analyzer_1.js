document.addEventListener('DOMContentLoaded', function() {
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    const uploadZone = document.getElementById('uploadZone');
    const fileInput = document.getElementById('qrcodeImage');
    const filePreview = document.getElementById('filePreview');
    const fileName = filePreview.querySelector('.file-name');
    const analyzerForm = document.getElementById('analyzerForm');
    const cameraCaptureData = document.getElementById('cameraCaptureData');

    const video = document.getElementById('cameraVideo');
    const canvas = document.getElementById('cameraCanvas');
    const scanCanvas = document.getElementById('scanCanvas');
    const cameraPlaceholder = document.getElementById('cameraPlaceholder');
    const captureBtn = document.getElementById('captureBtn');
    const switchCameraBtn = document.getElementById('switchCameraBtn');
    const capturePreview = document.getElementById('capturePreview');
    const capturedImage = document.getElementById('capturedImage');
    const retakeBtn = document.getElementById('retakeBtn');
    const scanStatus = document.getElementById('scanStatus');
    const scanFrame = document.getElementById('scanFrame');
    const qrDetected = document.getElementById('qrDetected');

    let stream = null;
    let facingMode = 'environment';
    let activeTab = 'camera';
    let scanInterval = null;
    let isScanning = false;
    let qrDetectedRecently = false;

    tabBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            const tab = this.dataset.tab;
            activeTab = tab;

            tabBtns.forEach(b => b.classList.remove('active'));
            this.classList.add('active');

            tabContents.forEach(content => {
                content.classList.remove('active');
                if (content.id === tab + '-tab') {
                    content.classList.add('active');
                }
            });

            if (tab === 'upload') {
                fileInput.required = true;
                stopCamera();
                stopScanning();
            } else {
                fileInput.required = false;
                startCamera();
            }
        });
    });

    async function startCamera() {
        try {
            if (stream) {
                stopCamera();
            }

            cameraPlaceholder.style.display = 'flex';
            scanStatus.style.display = 'none';

            stream = await navigator.mediaDevices.getUserMedia({
                video: {
                    facingMode: facingMode,
                    width: { ideal: 1280 },
                    height: { ideal: 720 }
                }
            });

            video.srcObject = stream;
            await video.play();

            video.style.display = 'block';
            cameraPlaceholder.style.display = 'none';
            captureBtn.style.display = 'inline-flex';
            scanStatus.style.display = 'block';

            const devices = await navigator.mediaDevices.enumerateDevices();
            const videoDevices = devices.filter(d => d.kind === 'videoinput');
            if (videoDevices.length > 1) {
                switchCameraBtn.style.display = 'inline-flex';
            }

            startScanning();

        } catch (err) {
            console.error('Camera error:', err);
            cameraPlaceholder.innerHTML = `
                <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="1.5">
                    <circle cx="12" cy="12" r="10"/>
                    <line x1="15" y1="9" x2="9" y2="15"/>
                    <line x1="9" y1="9" x2="15" y2="15"/>
                </svg>
                <p style="color: #ef4444;">Camera non accessible</p>
                <p class="camera-hint">Verifiez les permissions ou utilisez l'upload d'image</p>
            `;
        }
    }

    function stopCamera() {
        stopScanning();
        if (stream) {
            stream.getTracks().forEach(track => track.stop());
            stream = null;
        }
        video.srcObject = null;
        video.style.display = 'none';
    }

    function startScanning() {
        if (isScanning || !stream) return;
        isScanning = true;

        scanCanvas.width = video.videoWidth || 640;
        scanCanvas.height = video.videoHeight || 480;

        scanInterval = setInterval(() => {
            if (!stream || !video.videoWidth) return;

            scanCanvas.width = video.videoWidth;
            scanCanvas.height = video.videoHeight;
            const ctx = scanCanvas.getContext('2d');
            ctx.drawImage(video, 0, 0);

            const imageData = ctx.getImageData(0, 0, scanCanvas.width, scanCanvas.height);

            if (typeof jsQR !== 'undefined') {
                // Try with attemptBoth for better detection of inverted/normal QR codes
                let code = jsQR(imageData.data, imageData.width, imageData.height, {
                    inversionAttempts: 'attemptBoth'
                });

                // If not found, try with enhanced contrast
                if (!code) {
                    const enhancedData = enhanceImageContrast(imageData);
                    code = jsQR(enhancedData.data, enhancedData.width, enhancedData.height, {
                        inversionAttempts: 'attemptBoth'
                    });
                }

                if (code && code.data && !qrDetectedRecently) {
                    qrDetectedRecently = true;
                    onQRCodeDetected(code);
                }
            }
        }, 100);
    }

    function enhanceImageContrast(imageData) {
        const data = new Uint8ClampedArray(imageData.data);
        const factor = 1.3; // Contrast factor

        for (let i = 0; i < data.length; i += 4) {
            // Convert to grayscale
            const gray = 0.299 * data[i] + 0.587 * data[i + 1] + 0.114 * data[i + 2];

            // Apply contrast enhancement
            let newValue = factor * (gray - 128) + 128;
            newValue = Math.max(0, Math.min(255, newValue));

            // Apply threshold for better QR detection
            const threshold = newValue > 128 ? 255 : 0;

            data[i] = threshold;
            data[i + 1] = threshold;
            data[i + 2] = threshold;
        }

        return new ImageData(data, imageData.width, imageData.height);
    }

    function stopScanning() {
        isScanning = false;
        if (scanInterval) {
            clearInterval(scanInterval);
            scanInterval = null;
        }
    }

    function onQRCodeDetected(code) {
        stopScanning();

        scanFrame.classList.add('detected');
        qrDetected.style.display = 'flex';
        scanStatus.style.display = 'none';

        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        const ctx = canvas.getContext('2d');
        ctx.drawImage(video, 0, 0);

        const imageData = canvas.toDataURL('image/jpeg', 0.9);
        cameraCaptureData.value = imageData;

        setTimeout(() => {
            showAnalysisProgress();
        }, 600);
    }

    function showAnalysisProgress() {
        const cameraWrapper = document.querySelector('.camera-view-wrapper');
        const cameraControls = document.querySelector('.camera-controls');
        const analysisProgress = document.getElementById('analysisProgress');
        const progressBar = document.getElementById('progressBar');
        const progressPercent = document.getElementById('progressPercent');
        const submitBtn = document.getElementById('submitBtn');

        if (cameraWrapper) cameraWrapper.style.display = 'none';
        if (cameraControls) cameraControls.style.display = 'none';
        qrDetected.style.display = 'none';
        if (submitBtn) submitBtn.style.display = 'none';
        analysisProgress.style.display = 'block';

        let progress = 0;
        const steps = ['step1', 'step2', 'step3', 'step4'];
        let currentStep = 0;

        const progressInterval = setInterval(() => {
            progress += Math.random() * 8 + 2;
            if (progress > 95) progress = 95;

            progressBar.style.width = progress + '%';
            progressPercent.textContent = Math.round(progress) + '%';

            const stepThresholds = [25, 50, 75, 90];
            for (let i = 0; i < stepThresholds.length; i++) {
                if (progress >= stepThresholds[i] && i > currentStep - 1) {
                    const stepEl = document.getElementById(steps[i]);
                    if (stepEl && !stepEl.classList.contains('active')) {
                        stepEl.classList.add('active');
                        currentStep = i + 1;
                    }
                }
            }

            if (progress >= 95) {
                clearInterval(progressInterval);
                progressBar.style.width = '100%';
                progressPercent.textContent = '100%';
                steps.forEach(s => document.getElementById(s).classList.add('active'));

                setTimeout(() => {
                    analyzerForm.submit();
                }, 300);
            }
        }, 150);
    }

    function captureImage() {
        stopScanning();

        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        const ctx = canvas.getContext('2d');
        ctx.drawImage(video, 0, 0);

        const imageData = canvas.toDataURL('image/jpeg', 0.9);
        cameraCaptureData.value = imageData;

        capturedImage.src = imageData;
        capturePreview.style.display = 'block';
        video.style.display = 'none';
        captureBtn.style.display = 'none';
        switchCameraBtn.style.display = 'none';
        scanStatus.style.display = 'none';
    }

    function retakePhoto() {
        capturePreview.style.display = 'none';
        cameraCaptureData.value = '';
        video.style.display = 'block';
        captureBtn.style.display = 'inline-flex';
        scanStatus.style.display = 'block';
        qrDetectedRecently = false;
        scanFrame.classList.remove('detected');
        qrDetected.style.display = 'none';

        navigator.mediaDevices.enumerateDevices().then(devices => {
            const videoDevices = devices.filter(d => d.kind === 'videoinput');
            if (videoDevices.length > 1) {
                switchCameraBtn.style.display = 'inline-flex';
            }
        });

        startScanning();
    }

    async function switchCamera() {
        facingMode = facingMode === 'environment' ? 'user' : 'environment';
        qrDetectedRecently = false;
        await startCamera();
    }

    captureBtn.addEventListener('click', captureImage);
    retakeBtn.addEventListener('click', retakePhoto);
    switchCameraBtn.addEventListener('click', switchCamera);

    uploadZone.addEventListener('click', function(e) {
        if (e.target.closest('.remove-file')) return;
        fileInput.click();
    });

    uploadZone.addEventListener('dragover', function(e) {
        e.preventDefault();
        uploadZone.classList.add('dragover');
    });

    uploadZone.addEventListener('dragleave', function() {
        uploadZone.classList.remove('dragover');
    });

    uploadZone.addEventListener('drop', function(e) {
        e.preventDefault();
        uploadZone.classList.remove('dragover');
        if (e.dataTransfer.files.length) {
            fileInput.files = e.dataTransfer.files;
            updatePreview(e.dataTransfer.files[0]);
        }
    });

    fileInput.addEventListener('change', function() {
        if (this.files.length) {
            updatePreview(this.files[0]);
        }
    });

    function updatePreview(file) {
        fileName.textContent = file.name;
        filePreview.style.display = 'flex';
        uploadZone.classList.add('has-file');
    }

    window.removeFile = function() {
        fileInput.value = '';
        filePreview.style.display = 'none';
        uploadZone.classList.remove('has-file');
    };

    analyzerForm.addEventListener('submit', function(e) {
        if (activeTab === 'camera') {
            if (!cameraCaptureData.value) {
                e.preventDefault();
                alert('Veuillez capturer un QR code avec la camera ou basculez vers l\'upload d\'image.');
                return false;
            }
            fileInput.required = false;
        } else {
            if (!fileInput.files.length) {
                e.preventDefault();
                alert('Veuillez selectionner une image contenant un QR code.');
                return false;
            }
        }
    });

    if (activeTab === 'camera') {
        setTimeout(() => {
            startCamera();
        }, 500);
    }
});