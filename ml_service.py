from flask import Flask, request, jsonify
from dotenv import load_dotenv
import pandas as pd
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
from sentence_transformers import SentenceTransformer
from neo4j import GraphDatabase
import os

load_dotenv()

NEO4J_URI = os.getenv('NEO4J_URI')
NEO4J_USERNAME = os.getenv('NEO4J_USERNAME')
NEO4J_PASSWORD = os.getenv('NEO4J_PASSWORD')

# Initialize Flask app and Neo4j driver
app = Flask(__name__)
driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USERNAME, NEO4J_PASSWORD))
# Load SBERT model
model = SentenceTransformer('paraphrase-MiniLM-L6-v2')

# Function to fetch all profiles from Neo4j
def fetch_profiles_from_neo4j():
    query = """
    MATCH (u:User)-[:HAS_ROLE]->(role:Student)
    RETURN u.name AS name, u.email AS email, role.skills AS skills, role.cgpa AS cgpa, u.avatarUrl AS avatarUrl
    """
    with driver.session() as session:
        result = session.run(query)
        data = []
        for record in result:
            print(f"Raw CGPA value: {record['cgpa']}")  # Debugging line
            try:
                cgpa_value = float(record["cgpa"]) if record["cgpa"] is not None else 0.0
            except (ValueError, TypeError):
                cgpa_value = 0.0
            data.append({
                "name": record["name"],
                "email": record["email"],
                "skills": record["skills"] or [],
                "cgpa": cgpa_value,
                "avatarUrl": record["avatarUrl"] or '/images/default-avatar.png'
            })
    return data

# Function to fetch the target user's profile from Neo4j
def fetch_target_user_from_neo4j(email):
    query = """
    MATCH (u:User {email: $email})-[:HAS_ROLE]->(role:Student)
    RETURN role.skills AS skills, role.cgpa AS cgpa, u.avatarUrl AS avatarUrl
    """
    with driver.session() as session:
        record = session.run(query, {"email": email}).single()
        if record:
            try:
                target_skills = " ".join(record["skills"]) if record["skills"] else ""
                target_cgpa = float(record["cgpa"]) / 10.0  # Convert CGPA to float and normalize
                target_avatar_url = record["avatarUrl"]  # Fetch avatarUrl
            except (ValueError, TypeError):
                target_cgpa = 0.0  # Default CGPA value in case of error

            return {"skills": target_skills, "cgpa": target_cgpa, "avatarUrl": target_avatar_url}
        else:
            return None

# Similarity function
def hybrid_similarity(target_embedding, target_cgpa, data):
    # Compute SBERT similarity
    embeddings_matrix = np.vstack(data['SBERT_Embeddings'])
    skill_sim = cosine_similarity([target_embedding], embeddings_matrix).flatten()
    
    # Compute CGPA similarity
    cgpa_sim = 1 - abs(target_cgpa - data['Normalized_CGPA'])
    
    # Weighted combination
    combined_sim = 0.7 * skill_sim + 0.3 * cgpa_sim
    return combined_sim

@app.route('/recommendations', methods=['POST'])
def recommend_users_from_neo4j():
    request_data = request.json
    target_email = request_data['email']
    top_n = request_data.get('top_n', 5)

    try:
        # Fetch the target user's data from Neo4j
        target_user = fetch_target_user_from_neo4j(target_email)
        if not target_user:
            print(f"User with email {target_email} not found in Neo4j.")  # Debugging log
            return jsonify({"success": False, "message": "Target user not found."}), 404
        
        # Fetch all profiles excluding the current user
        profiles = fetch_profiles_from_neo4j()  # This is the function fetching all profiles
        profiles = [profile for profile in profiles if profile['email'] != target_email]  # Exclude the current user

        # Prepare DataFrame
        data = pd.DataFrame(profiles)
        data['Cleaned_Skills'] = data['skills'].apply(lambda x: " ".join(x))  # Convert skills list to string
        data['SBERT_Embeddings'] = list(model.encode(data['Cleaned_Skills'].tolist()))
        data['Normalized_CGPA'] = data['cgpa'] / 10.0  # Normalize CGPA

        # Process target user's data
        target_embedding = model.encode(target_user['skills'])
        target_cgpa = target_user['cgpa']  # Use normalized target CGPA

        # Compute similarities
        data['Similarity'] = hybrid_similarity(target_embedding, target_cgpa, data)

        # Get top recommendations
        recommendations = data.sort_values(by='Similarity', ascending=False).head(top_n)
        response = recommendations[['name', 'email', 'skills', 'cgpa', 'avatarUrl', 'Similarity']].to_dict(orient='records')

        return jsonify({"success": True, "recommendations": response})

    except Exception as e:
        print(f"Error fetching recommendations: {e}")  # Log the error
        return jsonify({
            "success": False,
            "message": "An error occurred while fetching recommendations. Please try again later.",
            "error": str(e)
        }), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
