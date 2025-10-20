class SafeDeleteApp {
    constructor() {
        this.currentUser = null;
        this.init();
    }

    init() {
        this.setupTabs();
        this.setupForms();
        this.setupButtons();
        this.setupModal();
    }

    setupTabs() {
        const tabBtns = document.querySelectorAll('.tab-btn');
        const tabContents = document.querySelectorAll('.tab-content');

        tabBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                const targetTab = btn.dataset.tab;

                tabBtns.forEach(b => b.classList.remove('active'));
                tabContents.forEach(c => c.classList.remove('active'));

                btn.classList.add('active');
                document.getElementById(targetTab).classList.add('active');
            });
        });
    }

    setupForms() {
        document.getElementById('signup-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleSignup();
        });

        document.getElementById('login-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleLogin();
        });
    }

    setupButtons() {
        document.getElementById('load-profile').addEventListener('click', () => {
            this.loadProfile();
        });

        document.getElementById('delete-profile').addEventListener('click', () => {
            this.deleteProfile();
        });

        document.getElementById('load-audit').addEventListener('click', () => {
            this.loadAuditLogs();
        });

        document.getElementById('show-db').addEventListener('click', () => {
            this.showDatabase();
        });

        document.getElementById('show-audit').addEventListener('click', () => {
            this.showAuditDatabase();
        });

        document.getElementById('crypto-shred').addEventListener('click', () => {
            this.simulateCryptoShred();
        });
    }

    setupModal() {
        const modal = document.getElementById('modal');
        const closeBtn = document.querySelector('.close');

        closeBtn.addEventListener('click', () => {
            modal.style.display = 'none';
        });

        window.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.style.display = 'none';
            }
        });
    }

    async handleSignup() {
        const form = document.getElementById('signup-form');
        const resultDiv = document.getElementById('signup-result');

        const formData = new FormData(form);
        const data = {
            name: document.getElementById('signup-name').value,
            email: document.getElementById('signup-email').value,
            phone: document.getElementById('signup-phone').value,
            password: document.getElementById('signup-password').value
        };

        try {
            this.showLoading(resultDiv);

            const response = await fetch('/signup', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });

            const result = await response.json();

            if (response.ok) {
                this.showResult(resultDiv, `Account created successfully! User ID: ${result.userId}`, 'success');
                form.reset();
            } else {
                this.showResult(resultDiv, result.error || 'Signup failed', 'error');
            }
        } catch (error) {
            this.showResult(resultDiv, 'Network error occurred', 'error');
        }
    }

    async handleLogin() {
        const form = document.getElementById('login-form');
        const resultDiv = document.getElementById('login-result');

        const data = {
            email: document.getElementById('login-email').value,
            password: document.getElementById('login-password').value
        };

        try {
            this.showLoading(resultDiv);

            const response = await fetch('/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });

            const result = await response.json();

            if (response.ok) {
                this.showResult(resultDiv, 'Login successful!', 'success');
                form.reset();
                this.currentUser = data.email;
            } else {
                this.showResult(resultDiv, result.error || 'Login failed', 'error');
            }
        } catch (error) {
            this.showResult(resultDiv, 'Network error occurred', 'error');
        }
    }

    async loadProfile() {
        const resultDiv = document.getElementById('profile-result');
        const profileDiv = document.getElementById('profile-info');

        try {
            this.showLoading(resultDiv);

            const response = await fetch('/me', {
                credentials: 'include'
            });

            const result = await response.json();

            if (response.ok) {
                profileDiv.innerHTML = `
                    <h3>Profile Information</h3>
                    <p><strong>ID:</strong> ${result.id}</p>
                    <p><strong>Name:</strong> ${result.name}</p>
                    <p><strong>Email:</strong> ${result.email}</p>
                    <p><strong>Phone:</strong> ${result.phone}</p>
                    <p><strong>Created:</strong> ${new Date(result.created_at).toLocaleString()}</p>
                `;
                this.showResult(resultDiv, 'Profile loaded successfully', 'success');
            } else {
                this.showResult(resultDiv, result.error || 'Failed to load profile', 'error');
                profileDiv.innerHTML = '';
            }
        } catch (error) {
            this.showResult(resultDiv, 'Network error occurred', 'error');
            profileDiv.innerHTML = '';
        }
    }

    async deleteProfile() {
        if (!confirm('Are you sure you want to delete all your data? This action cannot be undone.')) {
            return;
        }

        const resultDiv = document.getElementById('profile-result');

        try {
            this.showLoading(resultDiv);

            const response = await fetch('/me/delete', {
                method: 'POST',
                credentials: 'include'
            });

            const result = await response.json();

            if (response.ok) {
                this.showResult(resultDiv, 'Data deletion initiated', 'success');
                this.showDeletionProof(result);
                document.getElementById('profile-info').innerHTML = '';
            } else {
                this.showResult(resultDiv, result.error || 'Deletion failed', 'error');
            }
        } catch (error) {
            this.showResult(resultDiv, 'Network error occurred', 'error');
        }
    }

    showDeletionProof(result) {
        const modal = document.getElementById('modal');
        const modalBody = document.getElementById('modal-body');

        modalBody.innerHTML = `
            <h3>Data Deletion Proof</h3>
            <p>Your data has been successfully purged from the system.</p>
            <p><strong>Audit ID:</strong> ${result.auditId}</p>
            <p><strong>Proof Hash:</strong></p>
            <div class="proof-hash">${result.proof_hash}</div>
            <p><em>This proof hash can be used to verify the deletion was performed correctly.</em></p>
        `;

        modal.style.display = 'block';
    }

    async loadAuditLogs() {
        const userId = document.getElementById('audit-user-id').value;
        const logsDiv = document.getElementById('audit-logs');

        if (!userId) {
            logsDiv.innerHTML = '<p class="result error">Please enter a User ID</p>';
            return;
        }

        try {
            const response = await fetch(`/audit/${userId}`, {
                credentials: 'include'
            });

            const result = await response.json();

            if (response.ok) {
                this.displayAuditLogs(result.logs);
            } else {
                logsDiv.innerHTML = `<p class="result error">${result.error || 'Failed to load audit logs'}</p>`;
            }
        } catch (error) {
            logsDiv.innerHTML = '<p class="result error">Network error occurred</p>';
        }
    }

    displayAuditLogs(logs) {
        const logsDiv = document.getElementById('audit-logs');

        if (logs.length === 0) {
            logsDiv.innerHTML = '<p class="result info">No audit logs found</p>';
            return;
        }

        logsDiv.innerHTML = logs.map(log => `
            <div class="audit-log">
                <h4>${log.action}</h4>
                <p><strong>Timestamp:</strong> ${new Date(log.timestamp).toLocaleString()}</p>
                <p><strong>Performed by:</strong> ${log.performed_by}</p>
                ${log.deletion_method ? `<p><strong>Deletion method:</strong> ${log.deletion_method}</p>` : ''}
                ${log.affected_fields ? `<p><strong>Affected fields:</strong> ${log.affected_fields.join(', ')}</p>` : ''}
                ${log.notes ? `<p><strong>Notes:</strong> ${log.notes}</p>` : ''}
                <p><strong>Proof Hash:</strong></p>
                <div class="proof-hash">${log.proof_hash}</div>
            </div>
        `).join('');
    }

    async showDatabase() {
        const debugDiv = document.getElementById('debug-content');

        try {
            const response = await fetch('/debug/db', {
                credentials: 'include'
            });

            if (response.ok) {
                const data = await response.json();
                debugDiv.textContent = JSON.stringify(data, null, 2);
            } else {
                debugDiv.textContent = 'Failed to load database';
            }
        } catch (error) {
            debugDiv.textContent = 'Network error occurred';
        }
    }

    async showAuditDatabase() {
        const debugDiv = document.getElementById('debug-content');

        try {
            const response = await fetch('/debug/audit', {
                credentials: 'include'
            });

            if (response.ok) {
                const data = await response.json();
                debugDiv.textContent = JSON.stringify(data, null, 2);
            } else {
                debugDiv.textContent = 'Failed to load audit database';
            }
        } catch (error) {
            debugDiv.textContent = 'Network error occurred';
        }
    }

    async simulateCryptoShred() {
        if (!confirm('This will simulate destroying encryption keys. Continue?')) {
            return;
        }

        try {
            const response = await fetch('/simulate/crypto-shred', {
                method: 'POST',
                credentials: 'include'
            });

            const result = await response.json();

            if (response.ok) {
                alert('Crypto-shred simulation completed. Encryption keys have been destroyed.');
            } else {
                alert(result.error || 'Crypto-shred simulation failed');
            }
        } catch (error) {
            alert('Network error occurred');
        }
    }

    showLoading(element) {
        element.innerHTML = '<div class="loading"></div> Loading...';
        element.className = 'result info';
    }

    showResult(element, message, type) {
        element.innerHTML = message;
        element.className = `result ${type}`;
    }
}

document.addEventListener('DOMContentLoaded', () => {
    new SafeDeleteApp();
});
