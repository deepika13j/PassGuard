// =========================================================
// PASSGUARD
// PASSWORD SECURITY & RISK ANALYZER
// =========================================================


// =========================================================
// ELEMENTS
// =========================================================

const passwordInput = document.getElementById("passwordInput");
const togglePassword = document.getElementById("togglePassword");

const scoreElement = document.getElementById("score");
const progress = document.getElementById("progress");
const strength = document.getElementById("strength");

const entropyElement = document.getElementById("entropy");
const crackTimeElement = document.getElementById("crackTime");


// CHECKS

const lengthCheck = document.getElementById("lengthCheck");
const uppercaseCheck = document.getElementById("uppercaseCheck");
const lowercaseCheck = document.getElementById("lowercaseCheck");
const numberCheck = document.getElementById("numberCheck");
const specialCheck = document.getElementById("specialCheck");
const patternCheck = document.getElementById("patternCheck");


// DASHBOARD

const dashboardScore = document.getElementById("dashboardScore");
const dashboardRating = document.getElementById("dashboardRating");

const passwordQuality =
    document.getElementById("passwordQuality");

const attackResistance =
    document.getElementById("attackResistance");

const dashboardRisk =
    document.getElementById("dashboardRisk");

const recommendations =
    document.getElementById("recommendations");


// RISK ANALYSIS

const riskLevel =
    document.getElementById("riskLevel");

const bruteRisk =
    document.getElementById("bruteRisk");

const dictionaryRisk =
    document.getElementById("dictionaryRisk");

const patternRisk =
    document.getElementById("patternRisk");

const lengthRisk =
    document.getElementById("lengthRisk");


// ATTACK ANALYSIS

const threatStatus =
    document.getElementById("threatStatus");

const commonPasswordRisk =
    document.getElementById("commonPasswordRisk");

const sequenceRisk =
    document.getElementById("sequenceRisk");

const repeatRisk =
    document.getElementById("repeatRisk");

const predictabilityRisk =
    document.getElementById("predictabilityRisk");


// BREACH

const checkBreachBtn =
    document.getElementById("checkBreachBtn");

const breachResult =
    document.getElementById("breachResult");


// GENERATOR

const generatedPassword =
    document.getElementById("generatedPassword");

const copyBtn =
    document.getElementById("copyBtn");

const passwordLength =
    document.getElementById("passwordLength");

const lengthValue =
    document.getElementById("lengthValue");

const generateBtn =
    document.getElementById("generateBtn");


// SECURITY TIPS

const tipLength =
    document.getElementById("tipLength");

const tipCharacter =
    document.getElementById("tipCharacter");

const tipPattern =
    document.getElementById("tipPattern");



// =========================================================
// COMMON PASSWORD DATABASE
// =========================================================

const commonPasswords = [

    "password",
    "password123",
    "password1",
    "123456",
    "1234567",
    "12345678",
    "123456789",
    "1234567890",

    "qwerty",
    "qwerty123",
    "qwertyuiop",

    "admin",
    "admin123",

    "welcome",
    "welcome123",

    "letmein",
    "login",
    "user",

    "iloveyou",
    "monkey",
    "dragon",
    "football",
    "baseball",
    "master",
    "hello",
    "hello123",

    "sunshine",
    "princess",
    "superman",

    "pass",
    "pass123",

    "abc123",
    "test123",

    "guest",
    "root"

];



// =========================================================
// SHOW / HIDE PASSWORD
// =========================================================

if (togglePassword) {

    togglePassword.addEventListener("click", function () {

        if (passwordInput.type === "password") {

            passwordInput.type = "text";

            togglePassword.innerHTML =
                '<i class="fa-solid fa-eye-slash"></i>';

        } else {

            passwordInput.type = "password";

            togglePassword.innerHTML =
                '<i class="fa-solid fa-eye"></i>';

        }

    });

}



// =========================================================
// PASSWORD INPUT
// =========================================================

if (passwordInput) {

    passwordInput.addEventListener("input", function () {

        analyzePassword(passwordInput.value);

    });

}



// =========================================================
// CHECK IF CHARACTER TYPES EXIST
// =========================================================

function getCharacterTypes(password) {

    const hasUpper =
        /[A-Z]/.test(password);

    const hasLower =
        /[a-z]/.test(password);

    const hasNumber =
        /[0-9]/.test(password);

    const hasSpecial =
        /[^A-Za-z0-9]/.test(password);


    let types = 0;

    if (hasUpper) types++;
    if (hasLower) types++;
    if (hasNumber) types++;
    if (hasSpecial) types++;


    return {

        hasUpper,
        hasLower,
        hasNumber,
        hasSpecial,
        types

    };

}



// =========================================================
// ADVANCED PATTERN DETECTION
// =========================================================

function detectPatterns(password) {

    const lower =
        password.toLowerCase();


    // Repeated characters
    const repeatedCharacters =
        /(.)\1\1/.test(password);


    // Number sequences
    const sequentialNumbers =
        /1234|2345|3456|4567|5678|6789|9876|8765|7654|6543|5432|4321/
            .test(password);


    // Letter sequences
    const sequentialLetters =
        /abcd|bcde|cdef|defg|efgh|fghi|ghij|hijk|qwer|asdf|zxcv/
            .test(lower);


    // Repeated complete pattern
    const repeatedPattern =
        /^(.+)\1+$/.test(password);


    // Common password
    const commonPassword =
        commonPasswords.includes(lower);


    // Year pattern
    const yearPattern =
        /(19|20)\d{2}/.test(password);


    // Keyboard patterns
    const keyboardPattern =
        /qwerty|asdf|zxcv|qaz|wsx|edc/
            .test(lower);


    return {

        repeatedCharacters,
        sequentialNumbers,
        sequentialLetters,
        repeatedPattern,
        commonPassword,
        yearPattern,
        keyboardPattern

    };

}



// =========================================================
// CALCULATE ENTROPY
// =========================================================

function calculateEntropy(password, characterInfo) {

    let pool = 0;


    if (characterInfo.hasLower) {
        pool += 26;
    }

    if (characterInfo.hasUpper) {
        pool += 26;
    }

    if (characterInfo.hasNumber) {
        pool += 10;
    }

    if (characterInfo.hasSpecial) {
        pool += 32;
    }


    if (pool === 0) {
        return 0;
    }


    return Math.round(
        password.length * Math.log2(pool)
    );

}



// =========================================================
// CALCULATE SCORE
// =========================================================

function calculateScore(
    password,
    characterInfo,
    patterns,
    entropy
) {

    let score = 0;


    // -------------------------
    // LENGTH - 25 POINTS
    // -------------------------

    if (password.length >= 16) {

        score += 25;

    } else if (password.length >= 12) {

        score += 20;

    } else if (password.length >= 8) {

        score += 10;

    } else {

        score += 3;
    }



    // -------------------------
    // CHARACTER DIVERSITY
    // 25 POINTS
    // -------------------------

    score +=
        characterInfo.types * 6.25;



    // -------------------------
    // ENTROPY
    // 20 POINTS
    // -------------------------

    if (entropy >= 100) {

        score += 20;

    } else if (entropy >= 80) {

        score += 17;

    } else if (entropy >= 60) {

        score += 13;

    } else if (entropy >= 40) {

        score += 8;

    } else {

        score += 3;
    }



    // -------------------------
    // PATTERN RESISTANCE
    // 15 POINTS
    // -------------------------

    const hasPattern =
        patterns.repeatedCharacters ||
        patterns.sequentialNumbers ||
        patterns.sequentialLetters ||
        patterns.repeatedPattern ||
        patterns.commonPassword ||
        patterns.yearPattern ||
        patterns.keyboardPattern;


    if (!hasPattern) {

        score += 15;

    } else {

        score += 0;
    }



    // -------------------------
    // ATTACK RESISTANCE
    // 15 POINTS
    // -------------------------

    if (
        password.length >= 16 &&
        characterInfo.types >= 3 &&
        !hasPattern
    ) {

        score += 15;

    } else if (
        password.length >= 12 &&
        characterInfo.types >= 3
    ) {

        score += 10;

    } else {

        score += 4;
    }



    return Math.round(
        Math.min(score, 100)
    );

}



// =========================================================
// STRENGTH
// =========================================================

function getStrength(score) {

    if (score < 30) {

        return "VERY WEAK";

    } else if (score < 50) {

        return "WEAK";

    } else if (score < 70) {

        return "MODERATE";

    } else if (score < 85) {

        return "STRONG";

    } else {

        return "VERY STRONG";

    }

}



// =========================================================
// CRACK TIME
// =========================================================

function getCrackTime(entropy) {

    if (entropy < 28) {

        return "Instant";

    } else if (entropy < 36) {

        return "Seconds";

    } else if (entropy < 50) {

        return "Minutes";

    } else if (entropy < 65) {

        return "Hours";

    } else if (entropy < 80) {

        return "Days";

    } else if (entropy < 100) {

        return "Years";

    } else {

        return "Centuries";

    }

}



// =========================================================
// MAIN PASSWORD ANALYZER
// =========================================================

function analyzePassword(password) {


    if (password.length === 0) {

        resetAnalyzer();

        return;

    }


    // Character information

    const characterInfo =
        getCharacterTypes(password);


    // Advanced patterns

    const patterns =
        detectPatterns(password);


    // Pattern detected?

    const hasPattern =

        patterns.repeatedCharacters ||
        patterns.sequentialNumbers ||
        patterns.sequentialLetters ||
        patterns.repeatedPattern ||
        patterns.commonPassword ||
        patterns.yearPattern ||
        patterns.keyboardPattern;



    // Entropy

    const entropy =
        calculateEntropy(
            password,
            characterInfo
        );


    // Score

    const score =
        calculateScore(
            password,
            characterInfo,
            patterns,
            entropy
        );


    // Strength

    const strengthText =
        getStrength(score);


    // Crack time

    const crackTime =
        getCrackTime(entropy);



    // =====================================================
    // MAIN SCORE
    // =====================================================

    if (scoreElement) {

        scoreElement.textContent =
            score;

    }


    if (progress) {

        progress.style.width =
            score + "%";

    }


    if (strength) {

        strength.textContent =
            strengthText;

    }



    // =====================================================
    // SIX CHECKS
    // =====================================================

    updateCheck(
        lengthCheck,
        password.length >= 12
    );


    updateCheck(
        uppercaseCheck,
        characterInfo.hasUpper
    );


    updateCheck(
        lowercaseCheck,
        characterInfo.hasLower
    );


    updateCheck(
        numberCheck,
        characterInfo.hasNumber
    );


    updateCheck(
        specialCheck,
        characterInfo.hasSpecial
    );


    updateCheck(
        patternCheck,
        !hasPattern
    );



    // =====================================================
    // ENTROPY
    // =====================================================

    if (entropyElement) {

        entropyElement.textContent =
            entropy;

    }



    // =====================================================
    // CRACK TIME
    // =====================================================

    if (crackTimeElement) {

        crackTimeElement.textContent =
            crackTime;

    }



    // =====================================================
    // DASHBOARD
    // =====================================================

    updateDashboard(
        score,
        strengthText,
        crackTime,
        hasPattern
    );



    // =====================================================
    // RISK
    // =====================================================

    updateRiskAnalysis(
        password,
        score,
        patterns,
        hasPattern
    );



    // =====================================================
    // ATTACK ANALYSIS
    // =====================================================

    updateAttackAnalysis(
        password,
        patterns,
        hasPattern
    );



    // =====================================================
    // RECOMMENDATIONS
    // =====================================================

    updateRecommendations(
        password,
        characterInfo,
        patterns,
        hasPattern
    );



    // =====================================================
    // SECURITY TIPS
    // =====================================================

    updateSecurityTips(
        password
    );

}



// =========================================================
// UPDATE CHECK
// =========================================================

function updateCheck(element, valid) {

    if (!element) {
        return;
    }


    const icon =
        element.querySelector("i");


    if (valid) {

        element.classList.add("valid");

        element.classList.remove("invalid");


        if (icon) {

            icon.className =
                "fa-solid fa-circle-check";

        }

    } else {

        element.classList.remove("valid");

        element.classList.add("invalid");


        if (icon) {

            icon.className =
                "fa-solid fa-circle-xmark";

        }

    }

}



// =========================================================
// DASHBOARD
// =========================================================

function updateDashboard(
    score,
    strengthText,
    crackTime,
    hasPattern
) {


    if (dashboardScore) {

        dashboardScore.textContent =
            score;

    }


    if (dashboardRating) {

        dashboardRating.textContent =
            strengthText;

    }



    // Password quality

    if (passwordQuality) {

        if (score >= 85) {

            passwordQuality.textContent =
                "EXCELLENT";

        } else if (score >= 70) {

            passwordQuality.textContent =
                "STRONG";

        } else if (score >= 50) {

            passwordQuality.textContent =
                "MODERATE";

        } else {

            passwordQuality.textContent =
                "WEAK";

        }

    }



    // Attack resistance

    if (attackResistance) {

        if (
            crackTime === "Years" ||
            crackTime === "Centuries"
        ) {

            attackResistance.textContent =
                "HIGH";

        } else if (
            crackTime === "Days" ||
            crackTime === "Hours"
        ) {

            attackResistance.textContent =
                "MEDIUM";

        } else {

            attackResistance.textContent =
                "LOW";

        }

    }



    // Overall risk

    if (dashboardRisk) {

        if (
            score >= 85 &&
            !hasPattern
        ) {

            dashboardRisk.textContent =
                "LOW";

        } else if (
            score >= 60
        ) {

            dashboardRisk.textContent =
                "MEDIUM";

        } else {

            dashboardRisk.textContent =
                "HIGH";

        }

    }

}



// =========================================================
// RISK ANALYSIS
// =========================================================

function updateRiskAnalysis(
    password,
    score,
    patterns,
    hasPattern
) {


    // Brute force

    if (score >= 85) {

        bruteRisk.textContent =
            "LOW";

    } else if (score >= 60) {

        bruteRisk.textContent =
            "MEDIUM";

    } else {

        bruteRisk.textContent =
            "HIGH";

    }



    // Dictionary

    if (patterns.commonPassword) {

        dictionaryRisk.textContent =
            "HIGH";

    } else {

        dictionaryRisk.textContent =
            "LOW";

    }



    // Pattern

    if (hasPattern) {

        patternRisk.textContent =
            "HIGH";

    } else {

        patternRisk.textContent =
            "LOW";

    }



    // Length

    if (password.length >= 16) {

        lengthRisk.textContent =
            "LOW";

    } else if (password.length >= 12) {

        lengthRisk.textContent =
            "MEDIUM";

    } else {

        lengthRisk.textContent =
            "HIGH";

    }



    // Overall

    if (riskLevel) {

        if (
            score >= 85 &&
            !hasPattern
        ) {

            riskLevel.textContent =
                "LOW";

        } else if (
            score >= 60
        ) {

            riskLevel.textContent =
                "MEDIUM";

        } else {

            riskLevel.textContent =
                "HIGH";

        }

    }

}



// =========================================================
// ATTACK ANALYSIS
// =========================================================

function updateAttackAnalysis(
    password,
    patterns,
    hasPattern
) {


    // Common password

    if (patterns.commonPassword) {

        commonPasswordRisk.textContent =
            "HIGH";

    } else {

        commonPasswordRisk.textContent =
            "LOW";

    }



    // Sequence

    if (
        patterns.sequentialNumbers ||
        patterns.sequentialLetters ||
        patterns.keyboardPattern
    ) {

        sequenceRisk.textContent =
            "HIGH";

    } else {

        sequenceRisk.textContent =
            "LOW";

    }



    // Repeated

    if (
        patterns.repeatedCharacters ||
        patterns.repeatedPattern
    ) {

        repeatRisk.textContent =
            "HIGH";

    } else {

        repeatRisk.textContent =
            "LOW";

    }



    // Predictability

    let predictableScore = 0;


    if (patterns.commonPassword) {
        predictableScore += 2;
    }

    if (patterns.sequentialNumbers) {
        predictableScore += 2;
    }

    if (patterns.sequentialLetters) {
        predictableScore += 2;
    }

    if (patterns.repeatedCharacters) {
        predictableScore += 2;
    }

    if (patterns.yearPattern) {
        predictableScore += 1;
    }

    if (patterns.keyboardPattern) {
        predictableScore += 2;
    }



    if (predictableScore >= 3) {

        predictabilityRisk.textContent =
            "HIGH";

    } else if (predictableScore > 0) {

        predictabilityRisk.textContent =
            "MEDIUM";

    } else {

        predictabilityRisk.textContent =
            "LOW";

    }



    // Threat status

    if (threatStatus) {

        if (predictableScore >= 3) {

            threatStatus.textContent =
                "HIGH THREAT";

        } else if (predictableScore > 0) {

            threatStatus.textContent =
                "MODERATE";

        } else {

            threatStatus.textContent =
                "LOW THREAT";

        }

    }

}



// =========================================================
// SMART RECOMMENDATIONS
// =========================================================

function updateRecommendations(
    password,
    characterInfo,
    patterns,
    hasPattern
) {


    if (!recommendations) {
        return;
    }


    let tips = [];



    // Length

    if (password.length < 12) {

        tips.push(
            "Increase the password length to at least 12 characters."
        );

    } else if (password.length < 16) {

        tips.push(
            "Consider using 16 or more characters for stronger protection."
        );

    }



    // Uppercase

    if (!characterInfo.hasUpper) {

        tips.push(
            "Add at least one uppercase letter."
        );

    }



    // Lowercase

    if (!characterInfo.hasLower) {

        tips.push(
            "Add at least one lowercase letter."
        );

    }



    // Number

    if (!characterInfo.hasNumber) {

        tips.push(
            "Add numbers to increase character diversity."
        );

    }



    // Special

    if (!characterInfo.hasSpecial) {

        tips.push(
            "Add a special character such as !, @, # or $."
        );

    }



    // Common password

    if (patterns.commonPassword) {

        tips.push(
            "Avoid commonly used passwords because attackers can guess them quickly."
        );

    }



    // Sequences

    if (
        patterns.sequentialNumbers ||
        patterns.sequentialLetters
    ) {

        tips.push(
            "Avoid sequential patterns such as 1234 or abcd."
        );

    }



    // Keyboard

    if (patterns.keyboardPattern) {

        tips.push(
            "Avoid keyboard patterns such as qwerty or asdf."
        );

    }



    // Repeated

    if (
        patterns.repeatedCharacters ||
        patterns.repeatedPattern
    ) {

        tips.push(
            "Avoid repeating the same characters or password sections."
        );

    }



    // Year

    if (patterns.yearPattern) {

        tips.push(
            "Avoid using years because they are common password patterns."
        );

    }



    // Excellent

    if (tips.length === 0) {

        tips.push(
            "Excellent! Your password meets the major security requirements."
        );

    }



    recommendations.innerHTML = "";



    tips.slice(0, 5).forEach(function (tip) {

        const item =
            document.createElement("div");


        item.className =
            "recommendation-item";


        item.innerHTML = `
            <i class="fa-solid fa-circle-check"></i>
            <span>${tip}</span>
        `;


        recommendations.appendChild(item);

    });

}



// =========================================================
// DYNAMIC SECURITY TIPS
// =========================================================

function updateSecurityTips(password) {


    if (
        !tipLength ||
        !tipCharacter ||
        !tipPattern
    ) {

        return;

    }



    // Empty

    if (password.length === 0) {

        tipLength.querySelector("h3").textContent =
            "Use Long Passwords";

        tipLength.querySelector("p").textContent =
            "Use at least 12–16 characters for better protection against brute-force attacks.";


        tipCharacter.querySelector("h3").textContent =
            "Use More Character Types";

        tipCharacter.querySelector("p").textContent =
            "Combine uppercase, lowercase, numbers and special characters.";


        tipPattern.querySelector("h3").textContent =
            "Avoid Predictable Patterns";

        tipPattern.querySelector("p").textContent =
            "Avoid repeated characters, sequences and commonly used passwords.";

        return;

    }



    const info =
        getCharacterTypes(password);

    const patterns =
        detectPatterns(password);



    // Length

    if (password.length < 12) {

        tipLength.querySelector("h3").textContent =
            "Increase Password Length";

        tipLength.querySelector("p").textContent =
            "Your password is short. Use at least 12 characters, preferably 16 or more.";

    } else if (password.length < 16) {

        tipLength.querySelector("h3").textContent =
            "Consider a Longer Password";

        tipLength.querySelector("p").textContent =
            "Your password meets the minimum length. Using 16+ characters can provide stronger protection.";

    } else {

        tipLength.querySelector("h3").textContent =
            "Excellent Password Length";

        tipLength.querySelector("p").textContent =
            "Your password has a strong length, improving resistance against brute-force attacks.";

    }



    // Character variety

    if (info.types < 3) {

        tipCharacter.querySelector("h3").textContent =
            "Add More Character Types";

        tipCharacter.querySelector("p").textContent =
            "Use uppercase, lowercase, numbers and special characters to increase complexity.";

    } else if (info.types === 3) {

        tipCharacter.querySelector("h3").textContent =
            "Almost Fully Protected";

        tipCharacter.querySelector("p").textContent =
            "Your password uses several character types. Adding the missing type can improve strength.";

    } else {

        tipCharacter.querySelector("h3").textContent =
            "Strong Character Variety";

        tipCharacter.querySelector("p").textContent =
            "Your password uses uppercase, lowercase, numbers and special characters.";

    }



    // Pattern

    const hasPattern =

        patterns.repeatedCharacters ||
        patterns.sequentialNumbers ||
        patterns.sequentialLetters ||
        patterns.repeatedPattern ||
        patterns.commonPassword ||
        patterns.yearPattern ||
        patterns.keyboardPattern;


    if (hasPattern) {

        tipPattern.querySelector("h3").textContent =
            "Avoid Predictable Patterns";

        tipPattern.querySelector("p").textContent =
            "Your password contains a pattern that attackers may be able to guess more easily.";

    } else {

        tipPattern.querySelector("h3").textContent =
            "Good Pattern Resistance";

        tipPattern.querySelector("p").textContent =
            "No obvious repeated, sequential or common password patterns were detected.";

    }

}



// =========================================================
// RESET
// =========================================================

function resetAnalyzer() {


    if (scoreElement) {
        scoreElement.textContent = "0";
    }


    if (progress) {
        progress.style.width = "0%";
    }


    if (strength) {
        strength.textContent =
            "VERY WEAK";
    }


    if (entropyElement) {
        entropyElement.textContent =
            "0";
    }


    if (crackTimeElement) {
        crackTimeElement.textContent =
            "Instant";
    }



    updateCheck(lengthCheck, false);
    updateCheck(uppercaseCheck, false);
    updateCheck(lowercaseCheck, false);
    updateCheck(numberCheck, false);
    updateCheck(specialCheck, false);
    updateCheck(patternCheck, false);



    if (dashboardScore) {
        dashboardScore.textContent = "0";
    }


    if (dashboardRating) {
        dashboardRating.textContent = "UNKNOWN";
    }


    if (passwordQuality) {
        passwordQuality.textContent = "UNKNOWN";
    }


    if (attackResistance) {
        attackResistance.textContent = "UNKNOWN";
    }


    if (dashboardRisk) {
        dashboardRisk.textContent = "UNKNOWN";
    }


    if (riskLevel) {
        riskLevel.textContent = "UNKNOWN";
    }


    if (threatStatus) {
        threatStatus.textContent = "SCANNING";
    }


    if (bruteRisk) {
        bruteRisk.textContent = "—";
    }


    if (dictionaryRisk) {
        dictionaryRisk.textContent = "—";
    }


    if (patternRisk) {
        patternRisk.textContent = "—";
    }


    if (lengthRisk) {
        lengthRisk.textContent = "—";
    }


    if (commonPasswordRisk) {
        commonPasswordRisk.textContent = "—";
    }


    if (sequenceRisk) {
        sequenceRisk.textContent = "—";
    }


    if (repeatRisk) {
        repeatRisk.textContent = "—";
    }


    if (predictabilityRisk) {
        predictabilityRisk.textContent = "—";
    }



    if (recommendations) {

        recommendations.innerHTML = `
            <div class="recommendation-item">

                <i class="fa-solid fa-circle-info"></i>

                <span>
                    Enter a password to receive personalized
                    security recommendations.
                </span>

            </div>
        `;

    }



    updateSecurityTips("");

}



// =========================================================
// BREACH DETECTION
// =========================================================

if (checkBreachBtn) {

    checkBreachBtn.addEventListener(
        "click",
        checkPasswordBreach
    );

}


async function checkPasswordBreach() {


    const password =
        passwordInput.value;


    if (!password) {

        breachResult.className =
            "breach-result";


        breachResult.innerHTML = `
            <i class="fa-solid fa-circle-exclamation"></i>

            <span>
                Enter a password first.
            </span>
        `;

        return;

    }



    breachResult.className =
        "breach-result";


    breachResult.innerHTML = `
        <i class="fa-solid fa-spinner fa-spin"></i>

        <span>
            Checking breach database...
        </span>
    `;



    try {

        const encoder =
            new TextEncoder();


        const data =
            encoder.encode(password);


        const hashBuffer =
            await crypto.subtle.digest(
                "SHA-1",
                data
            );


        const hashArray =
            Array.from(
                new Uint8Array(hashBuffer)
            );


        const hash =
            hashArray
                .map(
                    byte =>
                        byte
                            .toString(16)
                            .padStart(2, "0")
                )
                .join("")
                .toUpperCase();


        const prefix =
            hash.substring(0, 5);


        const suffix =
            hash.substring(5);



        const response =
            await fetch(
                `https://api.pwnedpasswords.com/range/${prefix}`
            );


        if (!response.ok) {

            throw new Error(
                "Breach API request failed"
            );

        }



        const text =
            await response.text();


        const lines =
            text.split("\n");


        let found = false;

        let count = 0;



        for (let line of lines) {

            const parts =
                line.trim().split(":");


            if (
                parts.length === 2 &&
                parts[0].trim() === suffix
            ) {

                found = true;

                count =
                    parseInt(
                        parts[1].trim()
                    );

                break;

            }

        }



        if (found) {

            breachResult.className =
                "breach-result compromised";


            breachResult.innerHTML = `

                <i class="fa-solid fa-triangle-exclamation"></i>

                <span>

                    <strong>COMPROMISED</strong>

                    — This password has appeared
                    ${count.toLocaleString()}
                    times in known data breaches.

                </span>
            `;

        } else {

            breachResult.className =
                "breach-result safe";


            breachResult.innerHTML = `

                <i class="fa-solid fa-circle-check"></i>

                <span>

                    <strong>NOT FOUND</strong>

                    — No match was found in the
                    breach database.

                </span>
            `;

        }


    } catch (error) {

        console.error(error);


        breachResult.className =
            "breach-result";


        breachResult.innerHTML = `

            <i class="fa-solid fa-circle-exclamation"></i>

            <span>

                Unable to check the breach database.
                Try using Live Server.

            </span>
        `;

    }

}



// =========================================================
// SECURE PASSWORD GENERATOR
// =========================================================

const lowerChars =
    "abcdefghijklmnopqrstuvwxyz";

const upperChars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

const numberChars =
    "0123456789";

const specialChars =
    "!@#$%^&*()_+-=[]{}";



function getRandomCharacter(characters) {

    const array =
        new Uint32Array(1);


    crypto.getRandomValues(array);


    return characters[
        array[0] % characters.length
    ];

}



function generateSecurePassword(length) {


    let password = "";


    // Guarantee each character type

    password +=
        getRandomCharacter(
            lowerChars
        );


    password +=
        getRandomCharacter(
            upperChars
        );


    password +=
        getRandomCharacter(
            numberChars
        );


    password +=
        getRandomCharacter(
            specialChars
        );



    const allChars =
        lowerChars +
        upperChars +
        numberChars +
        specialChars;



    while (password.length < length) {

        password +=
            getRandomCharacter(
                allChars
            );

    }



    // Secure shuffle

    const array =
        password.split("");


    for (
        let i = array.length - 1;
        i > 0;
        i--
    ) {

        const random =
            new Uint32Array(1);


        crypto.getRandomValues(
            random
        );


        const j =
            random[0] % (i + 1);


        [
            array[i],
            array[j]
        ] = [
            array[j],
            array[i]
        ];

    }


    return array.join("");

}



// =========================================================
// GENERATE PASSWORD
// =========================================================

if (generateBtn) {

    generateBtn.addEventListener(
        "click",
        function () {

            const length =
                parseInt(
                    passwordLength.value
                );


            generatedPassword.value =
                generateSecurePassword(
                    length
                );

        }
    );

}



// =========================================================
// SLIDER
// =========================================================

if (passwordLength) {

    passwordLength.addEventListener(
        "input",
        function () {

            lengthValue.textContent =
                passwordLength.value;

        }
    );

}



// =========================================================
// COPY PASSWORD
// =========================================================

if (copyBtn) {

    copyBtn.addEventListener(
        "click",
        async function () {


            if (!generatedPassword.value) {

                return;

            }


            try {

                await navigator.clipboard.writeText(
                    generatedPassword.value
                );


                copyBtn.innerHTML =
                    '<i class="fa-solid fa-check"></i>';


                setTimeout(
                    function () {

                        copyBtn.innerHTML =
                            '<i class="fa-solid fa-copy"></i>';

                    },
                    1500
                );


            } catch (error) {

                console.error(error);

            }

        }
    );

}



// =========================================================
// INITIALIZE
// =========================================================

resetAnalyzer();


console.log(
    "PassGuard Advanced Security Analyzer is working!"
);