/*
 * Nom de l'application : CyberConfiance
 * Description : Fichier quiz.js du projet CyberConfiance
 * Produit de : MOA Digital Agency, www.myoneart.com
 * Fait par : Aisance KALONJI, www.aisancekalonji.com
 * Auditer par : La CyberConfiance, www.cyberconfiance.com

*/

/**
 * CyberConfiance
 * By MOA Digital Agency LLC
 * Developed by: Aisance KALONJI
 * Contact: moa@myoneart.com
 * www.myoneart.com
 * 
 * Quiz interactif de cybersecurite avec navigation et validation.
 */

let currentQuestionIndex = 1;
const totalQuestions = document.querySelectorAll('.question-card').length;

function updateProgress() {
    const progress = (currentQuestionIndex / totalQuestions) * 100;
    const progressBar = document.getElementById('progressBar');
    const currentQuestionSpan = document.getElementById('currentQuestion');
    
    if (progressBar) {
        progressBar.style.width = progress + '%';
    }
    if (currentQuestionSpan) {
        currentQuestionSpan.textContent = currentQuestionIndex;
    }
}

function showQuestion(questionNumber) {
    const questions = document.querySelectorAll('.question-card');
    questions.forEach((question, index) => {
        if (index + 1 === questionNumber) {
            question.style.display = 'block';
            question.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        } else {
            question.style.display = 'none';
        }
    });
    
    currentQuestionIndex = questionNumber;
    updateProgress();
}

function nextQuestion() {
    const currentQuestion = document.querySelector(`.question-card[data-question="${currentQuestionIndex}"]`);
    const selectedOption = currentQuestion.querySelector('input[type="radio"]:checked');
    
    if (!selectedOption) {
        alert('Veuillez sélectionner une réponse avant de continuer.');
        return;
    }
    
    if (currentQuestionIndex < totalQuestions) {
        showQuestion(currentQuestionIndex + 1);
    }
}

function previousQuestion() {
    if (currentQuestionIndex > 1) {
        showQuestion(currentQuestionIndex - 1);
    }
}

document.addEventListener('DOMContentLoaded', function() {
    updateProgress();
    
    const form = document.getElementById('quizForm');
    if (form) {
        form.addEventListener('submit', function(e) {
            const questions = document.querySelectorAll('.question-card');
            let allAnswered = true;
            
            questions.forEach((question, index) => {
                const selectedOption = question.querySelector('input[type="radio"]:checked');
                if (!selectedOption) {
                    allAnswered = false;
                    console.log('Question non répondue:', index + 1);
                }
            });
            
            if (!allAnswered) {
                e.preventDefault();
                alert('Veuillez répondre à toutes les questions avant de soumettre le quiz.');
                return false;
            }
        });
    }
    
    const options = document.querySelectorAll('.option-label');
    options.forEach(option => {
        option.addEventListener('click', function() {
            const parentCard = this.closest('.question-card');
            parentCard.querySelectorAll('.option-label').forEach(opt => {
                opt.classList.remove('selected');
            });
            this.classList.add('selected');
        });
    });
});

console.log('Quiz JS loaded!');
