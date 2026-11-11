// chat/static/js/chat.js
document.addEventListener('DOMContentLoaded', function () {
    const form = document.querySelector('form');
    const input = document.querySelector('input[name="content"]');
    const recipientPublicKey = {{ recipient_public_key|safe }}; // Passed from template

    form.addEventListener('submit', function (event) {
        event.preventDefault();
        const content = input.value;
        if (!content) return;

        // Use JSEncrypt (include <script src="https://cdn.jsdelivr.net/npm/jsencrypt@3.3.2/bin/jsencrypt.min.js"></script>)
        const encrypt = new JSEncrypt();
        encrypt.setPublicKey(`-----BEGIN PUBLIC KEY-----\n${recipientPublicKey[0]}\n${recipientPublicKey[1]}\n-----END PUBLIC KEY-----`);
        const encrypted = encrypt.encrypt(content);

        const hiddenInput = document.createElement('input');
        hiddenInput.type = 'hidden';
        hiddenInput.name = 'encrypted_content';
        hiddenInput.value = encrypted;
        form.appendChild(hiddenInput);

        form.submit();
    });
});