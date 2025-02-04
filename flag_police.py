import pandas as pd
import argparse
from collections import defaultdict
from itertools import combinations

pair_detect = 3 # definit le seuil de detection des paires.

# Charger le fichier CSV
def load_data(file_path):
    df = pd.read_csv(file_path)
    df['date'] = pd.to_datetime(df['date'], format="%Y-%m-%d %H:%M:%S.%f", errors='coerce')
    return df


# Étape 1 : Détection des flags trop rapprochés par challenge
def detect_suspicious_flags(df, delay, excluded_challenges, included_range):
    if included_range:
        min_id, max_id = included_range
        df = df[(df['challenge_id'] >= min_id) & (df['challenge_id'] <= max_id)]  # Filtrer par intervalle
    df = df[~df['challenge_id'].isin(excluded_challenges)]  # Exclure les challenges spécifiés
    df = df.sort_values(by=['challenge_id', 'date'])  # Trier par challenge et date

    suspicious_flags = defaultdict(set)  # {challenge_id: {user1, user2, ...}}
    first_flags = {}  # Stocker le premier flaggeur par challenge

    for challenge_id, group in df.groupby('challenge_id'):
        first_flags[challenge_id] = group.iloc[0]['user_id']  # Premier à flagger ce challenge

        users_recent_flags = []  # Stocker (user_id, date) trié
        for _, row in group.iterrows():
            user_id, flag_time = row['user_id'], row['date']

            # Vérifier si un autre joueur a flaggué récemment sur ce challenge
            to_remove = []
            for prev_user, prev_time in users_recent_flags:
                delta = (flag_time - prev_time).total_seconds()

                if delta < delay:
                    suspicious_flags[challenge_id].update([user_id, prev_user])
                else:
                    to_remove.append((prev_user, prev_time))  # Trop vieux, on l’enlève

            # Nettoyage : On ne garde que les flags dans la fenêtre de temps
            users_recent_flags = [entry for entry in users_recent_flags if entry not in to_remove]

            # Ajouter le flag actuel
            users_recent_flags.append((user_id, flag_time))

    return suspicious_flags, first_flags


# Étape 2 : Analyse des récurrences entre utilisateurs
def analyze_recurrences(suspicious_flags, first_flags):
    user_pairs = defaultdict(lambda: [0, defaultdict(int)])  # { (userA, userB) : [count, {patient_zero: occurrences}] }

    for challenge_id, users in suspicious_flags.items():
        first_user = first_flags.get(challenge_id, None)  # Assurer qu'on récupère un ID valide
        for user_pair in combinations(users, 2):  # Génère toutes les paires possibles
            user_pairs[tuple(sorted(user_pair))][0] += 1  # On trie pour éviter (A, B) ≠ (B, A)

    # Exclure les paires qui n'ont flagué ensemble qu'une seule fois
    user_pairs = {pair: data for pair, data in user_pairs.items() if data[0] > pair_detect}

    return user_pairs


# Exporter les résultats dans un fichier CSV
def export_results(suspicious_flags, user_pairs, output_file="suspicious_flags.csv"):
    rows = []
    for challenge_id, users in suspicious_flags.items():
        rows.append({"challenge_id": challenge_id, "users": ", ".join(map(str, sorted(users)))})

    df_suspicious = pd.DataFrame(rows)
    df_suspicious.to_csv(output_file, index=False)

    user_pair_rows = []
    for (userA, userB), (count, _) in user_pairs.items():
        user_pair_rows.append({"user_1": userA, "user_2": userB, "common_flags": count})

    df_user_pairs = pd.DataFrame(user_pair_rows)
    user_pair_output = output_file.replace(".csv", "_pairs.csv")
    df_user_pairs.to_csv(user_pair_output, index=False)

    print(f"📁 Résultats exportés dans {output_file} et {user_pair_output}")


# Affichage des résultats
def display_results(suspicious_flags, user_pairs):
    if not suspicious_flags:
        print("✅ Aucune activité suspecte détectée.")
    else:
        print("🚨 Activités suspectes détectées par challenge :")
        for challenge_id, users in suspicious_flags.items():
            print(f"  - Challenge {challenge_id}: Joueurs suspects {sorted(users)}")

    if not user_pairs:
        print("\n✅ Aucun groupe de joueurs flaggant ensemble fréquemment.")
    else:
        print("\n🔍 Joueurs flaggant souvent ensemble :")
        for (userA, userB), (count, _) in sorted(user_pairs.items(), key=lambda x: x[1][0], reverse=True):
            print(f"  - {userA} & {userB} ont flagué ensemble {count} fois.")


# Exécution du script
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", type=str, required=True, help="Chemin du fichier CSV")
    parser.add_argument("--delay", type=int, required=True, help="Délai en secondes pour la détection")
    parser.add_argument("--exclude", type=str, default="",
                        help="Liste des challenges à exclure (séparés par des virgules)")
    parser.add_argument("--include", type=str, default="", help="Intervalle des challenges à inclure (format min:max)")
    parser.add_argument("--output", type=str, default="suspicious_flags.csv", help="Fichier de sortie CSV")

    args = parser.parse_args()
    excluded_challenges = list(map(int, args.exclude.split(","))) if args.exclude else []
    included_range = tuple(map(int, args.include.split(":"))) if args.include else None

    df = load_data(args.file)
    suspicious_flags, first_flags = detect_suspicious_flags(df, args.delay, excluded_challenges, included_range)
    user_pairs = analyze_recurrences(suspicious_flags, first_flags)
    display_results(suspicious_flags, user_pairs)
    export_results(suspicious_flags, user_pairs, args.output)
