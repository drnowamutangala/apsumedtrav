#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════╗
║  APSUMEDTRAV → Wizard Stepper (7 étapes)          ║
║  Usage: python3 transform_wizard.py               ║
╚═══════════════════════════════════════════════════╝
"""
import shutil

FILE = 'APSUMEDTRAV.html'
BACKUP = 'APSUMEDTRAV_TABS_BACKUP.html'

with open(FILE, 'r', encoding='utf-8') as f:
    html = f.read()

shutil.copy2(FILE, BACKUP)
print(f"📦 Sauvegarde → {BACKUP}")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 1. INJECTION CSS WIZARD (avant </style>)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

WIZARD_CSS = """

/* ═══════════════════════════════════════════════════
   WIZARD STEPPER - Navigation par étapes
   ═══════════════════════════════════════════════════ */

/* Masquer les anciens onglets horizontaux */
.tabs { display: none !important; }

/* Conteneur du wizard */
.wizard-wrap {
    background: #fff;
    border-radius: 16px;
    padding: 22px 18px;
    margin-bottom: 22px;
    box-shadow: 0 2px 15px rgba(0,0,0,0.06);
}

/* Barre horizontale des étapes */
.wizard-bar {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    position: relative;
    margin-bottom: 18px;
}

/* Ligne de connexion entre cercles */
.wizard-bar::before {
    content: '';
    position: absolute;
    top: 21px;
    left: 50px;
    right: 50px;
    height: 3px;
    background: #e0e0e0;
    z-index: 0;
}

/* Chaque étape (cercle + label) */
.wz-s {
    display: flex;
    flex-direction: column;
    align-items: center;
    position: relative;
    z-index: 1;
    cursor: pointer;
    flex: 1;
}

/* Cercle numéroté */
.wz-s .wz-n {
    width: 42px;
    height: 42px;
    border-radius: 50%;
    background: #fff;
    color: #bbb;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 700;
    font-size: 15px;
    border: 3px solid #e0e0e0;
    transition: all 0.35s ease;
}

/* Label sous le cercle */
.wz-s .wz-l {
    margin-top: 8px;
    font-size: 10.5px;
    color: #bbb;
    text-align: center;
    font-weight: 600;
    max-width: 82px;
    line-height: 1.3;
    transition: all 0.35s ease;
}

/* ── État ACTIF ── */
.wz-s.wz-active .wz-n {
    background: linear-gradient(135deg, #667eea, #764ba2);
    color: #fff;
    border-color: #764ba2;
    box-shadow: 0 0 0 5px rgba(102, 126, 234, 0.22);
    transform: scale(1.12);
}
.wz-s.wz-active .wz-l {
    color: #667eea;
    font-weight: 700;
}

/* ── État COMPLÉTÉ ── */
.wz-s.wz-done .wz-n {
    background: #28a745;
    color: #fff;
    border-color: #28a745;
}
.wz-s.wz-done .wz-l {
    color: #28a745;
}

/* Hover */
.wz-s:not(.wz-active):not(.wz-done):hover .wz-n {
    border-color: #aaa;
    color: #777;
}

/* Barre de progression globale */
.wz-pb {
    height: 5px;
    background: #e9ecef;
    border-radius: 4px;
    overflow: hidden;
}
.wz-pb-fill {
    height: 100%;
    background: linear-gradient(90deg, #667eea, #764ba2);
    border-radius: 4px;
    transition: width 0.5s cubic-bezier(0.4, 0, 0.2, 1);
    width: 0%;
}

/* Navigation Précédent / Suivant */
.wz-nav {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-top: 28px;
    padding: 20px 0 0 0;
    border-top: 2px solid #f0f2f5;
}

.wz-btn {
    padding: 12px 28px;
    border: none;
    border-radius: 10px;
    font-size: 14.5px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.25s ease;
    display: inline-flex;
    align-items: center;
    gap: 7px;
    font-family: inherit;
}

.wz-btn-prev {
    background: #f0f2f5;
    color: #555;
}
.wz-btn-prev:hover {
    background: #e2e5ea;
    transform: translateX(-2px);
}

.wz-btn-next {
    background: linear-gradient(135deg, #667eea, #764ba2);
    color: #fff;
    box-shadow: 0 3px 10px rgba(102, 126, 234, 0.28);
}
.wz-btn-next:hover {
    transform: translateY(-2px);
    box-shadow: 0 6px 18px rgba(102, 126, 234, 0.38);
}

.wz-btn-save {
    background: linear-gradient(135deg, #28a745, #20c997);
    color: #fff;
    box-shadow: 0 3px 10px rgba(40, 167, 69, 0.28);
    font-size: 15px;
    padding: 13px 34px;
}
.wz-btn-save:hover {
    transform: translateY(-2px);
    box-shadow: 0 6px 18px rgba(40, 167, 69, 0.38);
}

.wz-indicator {
    color: #aaa;
    font-size: 13px;
    font-weight: 500;
}

/* Animation d'apparition des sections */
.tab-content {
    animation: wzFadeIn 0.35s ease;
}
@keyframes wzFadeIn {
    from { opacity: 0; transform: translateY(8px); }
    to   { opacity: 1; transform: translateY(0); }
}

/* ── Responsive ── */
@media (max-width: 768px) {
    .wizard-bar {
        overflow-x: auto;
        -webkit-overflow-scrolling: touch;
        padding-bottom: 8px;
        gap: 2px;
    }
    .wizard-bar::before { left: 30px; right: 30px; }
    .wz-s .wz-n { width: 34px; height: 34px; font-size: 12px; }
    .wz-s .wz-l { font-size: 8.5px; max-width: 58px; }
    .wz-btn { padding: 9px 18px; font-size: 13px; }
    .wizard-wrap { padding: 15px 10px; }
    .wz-nav { flex-wrap: wrap; gap: 10px; justify-content: center; }
}
"""

assert '</style>' in html, "❌ </style> non trouvé !"
html = html.replace('</style>', WIZARD_CSS + '\n</style>', 1)
print("✅ CSS wizard injecté")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 2. INJECTION JS WIZARD (avant </body>)
#    → Crée dynamiquement le stepper + boutons nav
#    → Surcharge openTab() existant
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

WIZARD_JS = r"""

<!-- ═══ WIZARD STEPPER SCRIPT ═══ -->
<script>
(function() {
    'use strict';

    // ──── Les 7 étapes du dossier médical ────
    var STEPS = [
        { id: 'identification', icon: '\u{1F4CB}', label: 'Identification' },
        { id: 'antecedents',    icon: '\u{1F4C1}', label: 'Antécédents' },
        { id: 'clinique',       icon: '\u{1FA7A}', label: 'Examen Clinique' },
        { id: 'paraclinique',   icon: '\u{1F52C}', label: 'Paraclinique' },
        { id: 'vaccinations',   icon: '\u{1F489}', label: 'Vaccinations' },
        { id: 'risques',        icon: '\u26A0\uFE0F', label: 'Risques Pro' },
        { id: 'conclusion',     icon: '\u2705',    label: 'Conclusion' }
    ];

    var cur = 0;

    // ──── Construire le stepper dans le DOM ────
    function buildStepper() {
        var firstTab = document.querySelector('.tab-content');
        if (!firstTab) { console.warn('Wizard: aucun .tab-content trouvé'); return; }

        var wrap = document.createElement('div');
        wrap.className = 'wizard-wrap';
        wrap.id = 'wizardWrap';

        var h = '<div class="wizard-bar" id="wizardBar">';
        for (var i = 0; i < STEPS.length; i++) {
            var cls = (i === 0) ? 'wz-s wz-active' : 'wz-s';
            h += '<div class="' + cls + '" data-idx="' + i + '">';
            h += '<div class="wz-n">' + (i + 1) + '</div>';
            h += '<div class="wz-l">' + STEPS[i].icon + ' ' + STEPS[i].label + '</div>';
            h += '</div>';
        }
        h += '</div>';
        h += '<div class="wz-pb"><div class="wz-pb-fill" id="wzPbFill"></div></div>';

        wrap.innerHTML = h;
        firstTab.parentNode.insertBefore(wrap, firstTab);

        // Clic sur chaque étape
        var stepEls = wrap.querySelectorAll('.wz-s');
        for (var j = 0; j < stepEls.length; j++) {
            (function(el) {
                el.addEventListener('click', function() {
                    goTo(parseInt(el.getAttribute('data-idx')));
                });
            })(stepEls[j]);
        }
    }

    // ──── Naviguer vers l'étape idx ────
    function goTo(idx) {
        if (idx < 0 || idx >= STEPS.length) return;
        if (idx > cur + 1) return; // pas de saut

        // Masquer tous les onglets
        var tabs = document.querySelectorAll('.tab-content');
        for (var i = 0; i < tabs.length; i++) {
            tabs[i].style.display = 'none';
            tabs[i].classList.remove('active');
        }

        // Afficher l'onglet cible
        var target = document.getElementById(STEPS[idx].id);
        if (target) {
            target.style.display = 'block';
            target.classList.add('active');
        }

        // Mettre à jour les cercles du stepper
        var circles = document.querySelectorAll('.wz-s');
        for (var k = 0; k < circles.length; k++) {
            circles[k].classList.remove('wz-active', 'wz-done');
            var numEl = circles[k].querySelector('.wz-n');
            if (k < idx) {
                circles[k].classList.add('wz-done');
                numEl.textContent = '\u2713'; // ✓
            } else if (k === idx) {
                circles[k].classList.add('wz-active');
                numEl.textContent = String(k + 1);
            } else {
                numEl.textContent = String(k + 1);
            }
        }

        // Barre de progression
        var pct = (idx === 0) ? 0 : Math.round((idx / (STEPS.length - 1)) * 100);
        var fill = document.getElementById('wzPbFill');
        if (fill) fill.style.width = pct + '%';

        cur = idx;
        addNavButtons();

        // Scroll doux vers le haut
        var wrap = document.getElementById('wizardWrap');
        if (wrap) {
            setTimeout(function() {
                wrap.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }, 60);
        }
    }

    // ──── Ajouter Précédent / Étape X/7 / Suivant ────
    function addNavButtons() {
        // Supprimer les anciens boutons
        var oldNavs = document.querySelectorAll('.wz-nav');
        for (var r = 0; r < oldNavs.length; r++) oldNavs[r].remove();

        var tab = document.getElementById(STEPS[cur].id);
        if (!tab) return;

        var nav = document.createElement('div');
        nav.className = 'wz-nav';

        // Bouton Précédent
        if (cur > 0) {
            var prev = document.createElement('button');
            prev.type = 'button';
            prev.className = 'wz-btn wz-btn-prev';
            prev.innerHTML = '\u2190 Précédent';
            prev.addEventListener('click', function() { goTo(cur - 1); });
            nav.appendChild(prev);
        } else {
            nav.appendChild(document.createElement('div'));
        }

        // Indicateur central
        var ind = document.createElement('span');
        ind.className = 'wz-indicator';
        ind.textContent = '\u00C9tape ' + (cur + 1) + ' / ' + STEPS.length;
        nav.appendChild(ind);

        // Bouton Suivant ou Enregistrer
        if (cur < STEPS.length - 1) {
            var next = document.createElement('button');
            next.type = 'button';
            next.className = 'wz-btn wz-btn-next';
            next.innerHTML = 'Suivant \u2192';
            next.addEventListener('click', function() { goTo(cur + 1); });
            nav.appendChild(next);
        } else {
            var save = document.createElement('button');
            save.type = 'button';
            save.className = 'wz-btn wz-btn-save';
            save.innerHTML = '\u{1F4BE} Enregistrer le dossier';
            save.addEventListener('click', function() {
                if (typeof window.sauvegarderDossier === 'function') {
                    window.sauvegarderDossier();
                } else if (typeof window.saveDossier === 'function') {
                    window.saveDossier();
                } else {
                    var btn = document.querySelector('[onclick*="sauvegarder"], [onclick*="save"], .btn-save, #btn-save');
                    if (btn) btn.click();
                    else alert('Fonction de sauvegarde non trouvée');
                }
            });
            nav.appendChild(save);
        }

        tab.appendChild(nav);
    }

    // ──── API globale ────
    window.goToStep = goTo;
    window.nextStep = function() { goTo(cur + 1); };
    window.prevStep = function() { goTo(cur - 1); };
    window.getCurrentWizardStep = function() { return cur; };

    // Surcharger l'ancien openTab pour compatibilité
    var _origOpenTab = window.openTab;
    window.openTab = function(evt, tabName) {
        for (var i = 0; i < STEPS.length; i++) {
            if (STEPS[i].id === tabName) { goTo(i); return; }
        }
        // Fallback si le tab n'est pas dans le wizard
        if (typeof _origOpenTab === 'function') _origOpenTab(evt, tabName);
    };

    // ──── Initialisation ────
    function init() {
        buildStepper();
        goTo(0);
        console.log('%c\u{1F9D9} Wizard Stepper actif (' + STEPS.length + ' étapes)', 'color:#667eea;font-weight:bold;font-size:13px');
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        setTimeout(init, 100);
    }

})();
</script>
"""

assert '</body>' in html, "❌ </body> non trouvé !"
html = html.replace('</body>', WIZARD_JS + '\n</body>', 1)
print("✅ JavaScript wizard injecté")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SAUVEGARDE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

with open(FILE, 'w', encoding='utf-8') as f:
    f.write(html)

lines_added = html.count('\n') - open(BACKUP).read().count('\n')
print(f"\n{'='*50}")
print(f"🎉 TRANSFORMATION TERMINÉE !")
print(f"{'='*50}")
print(f"   📄 Modifié  : {FILE}")
print(f"   📦 Backup   : {BACKUP}")
print(f"   📊 +{lines_added} lignes ajoutées")
print(f"   🔧 Bug corrigé : onglet 'Examen Clinique' maintenant accessible")
print(f"\n   ① ── ② ── ③ ── ④ ── ⑤ ── ⑥ ── ⑦")
print(f"   [← Précédent]  Étape X/7  [Suivant →]")
print(f"   ████████░░░░░░░ progression")
print(f"\n   Ouvrez dans le navigateur pour tester ! 🌐")

