"""
Vector Store for CIM Knowledge Base
Uses ChromaDB for semantic search of CIM field definitions
"""
import json
from pathlib import Path
from typing import List, Dict, Optional

# Try to import ChromaDB and sentence-transformers
try:
    import chromadb
    from chromadb.config import Settings
    CHROMADB_AVAILABLE = True
except ImportError:
    CHROMADB_AVAILABLE = False

try:
    from sentence_transformers import SentenceTransformer
    SENTENCE_TRANSFORMERS_AVAILABLE = True
except ImportError:
    SENTENCE_TRANSFORMERS_AVAILABLE = False


class CIMVectorStore:
    """Vector store for CIM knowledge base with semantic search capabilities."""
    
    def __init__(self, knowledge_dir: str = "data/cim_knowledge", db_dir: str = "data/vector_db"):
        """Initialize the CIM vector store."""
        self.knowledge_dir = Path(knowledge_dir)
        self.db_dir = Path(db_dir)
        self.db_dir.mkdir(parents=True, exist_ok=True)
        
        self.available = CHROMADB_AVAILABLE and SENTENCE_TRANSFORMERS_AVAILABLE
        
        if self.available:
            # Initialize embedding model
            self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
            
            # Initialize ChromaDB
            self.client = chromadb.PersistentClient(
                path=str(self.db_dir),
                settings=Settings(anonymized_telemetry=False)
            )
            
            # Get or create collection
            self.collection = self.client.get_or_create_collection(
                name="cim_knowledge",
                metadata={"description": "Splunk CIM field definitions and mappings"}
            )
            
            # Load CIM knowledge if collection is empty
            if self.collection.count() == 0:
                self.load_cim_knowledge()
        else:
            self.embedding_model = None
            self.client = None
            self.collection = None
    
    def load_cim_knowledge(self):
        """Load all CIM data model definitions into the vector store."""
        if not self.available:
            return
            
        print("Loading CIM knowledge base...")
        
        documents = []
        metadatas = []
        ids = []
        
        for json_file in self.knowledge_dir.glob("*.json"):
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    data_model = json.load(f)
                
                model_name = data_model.get("data_model", "")
                constraints = data_model.get("constraints", {})
                constraint_search = constraints.get("search", "") if isinstance(constraints, dict) else ""
                
                for dataset in data_model.get("datasets", []):
                    dataset_name = dataset.get("name", "")
                    tags = dataset.get("tags", [])
                    
                    for field in dataset.get("fields", []):
                        field_name = field.get("name", "")
                        field_desc = field.get("description", "")
                        field_type = field.get("type", "")
                        requirement = field.get("requirement", "")
                        prescribed_values = field.get("prescribed_values", [])
                        field_flag = field.get("flag", "extracted")
                        
                        doc_text = f"""
Data Model: {model_name}
Dataset: {dataset_name}
Field: {field_name}
Description: {field_desc}
Type: {field_type}
Requirement: {requirement}
Field Flag: {field_flag}
Tags: {', '.join(tags)}
"""
                        if prescribed_values:
                            doc_text += f"Prescribed Values: {', '.join(prescribed_values)}\n"
                        
                        if field_flag == "inherited":
                            doc_text += "Mapping Type: This field is inherited and should NOT be mapped.\n"
                        elif field_flag == "extracted":
                            doc_text += "Mapping Type: Use FIELDALIAS for direct extraction.\n"
                        elif field_flag == "calculated":
                            doc_text += "Mapping Type: MUST use EVAL (calculated field).\n"
                        
                        metadata = {
                            "data_model": model_name,
                            "dataset": dataset_name,
                            "field_name": field_name,
                            "field_type": field_type,
                            "requirement": requirement,
                            "field_flag": field_flag,
                            "tags": ",".join(tags),
                            "source_file": json_file.name,
                            "constraint_search": constraint_search
                        }
                        
                        if prescribed_values:
                            metadata["prescribed_values"] = ",".join(prescribed_values)
                        
                        doc_id = f"{model_name}_{dataset_name}_{field_name}"
                        
                        documents.append(doc_text.strip())
                        metadatas.append(metadata)
                        ids.append(doc_id)
                
                print(f"  ✓ Loaded {model_name} data model")
                
            except Exception as e:
                print(f"  ✗ Error loading {json_file.name}: {e}")
        
        if documents:
            embeddings = self.embedding_model.encode(documents).tolist()
            
            self.collection.add(
                documents=documents,
                embeddings=embeddings,
                metadatas=metadatas,
                ids=ids
            )
            
            print(f"\n✓ Loaded {len(documents)} CIM field definitions into vector store")
    
    def search_similar_fields(self, query: str, n_results: int = 10, 
                             data_model_filter: Optional[str] = None) -> List[Dict]:
        """Search for CIM fields similar to the query."""
        if not self.available:
            return []
            
        query_embedding = self.embedding_model.encode([query]).tolist()[0]
        
        where_filter = None
        if data_model_filter:
            where_filter = {"data_model": data_model_filter}
        
        results = self.collection.query(
            query_embeddings=[query_embedding],
            n_results=n_results,
            where=where_filter
        )
        
        formatted_results = []
        if results and results['documents']:
            for i in range(len(results['documents'][0])):
                formatted_results.append({
                    "document": results['documents'][0][i],
                    "metadata": results['metadatas'][0][i],
                    "distance": results['distances'][0][i] if 'distances' in results else None
                })
        
        return formatted_results
    
    def get_all_data_models(self) -> List[str]:
        """Get list of all available data models."""
        if not self.available:
            return []
            
        results = self.collection.get()
        
        if results and results['metadatas']:
            data_models = set(meta.get('data_model', '') for meta in results['metadatas'])
            return sorted(list(data_models))
        
        return []
    
    def get_stats(self) -> Dict:
        """Get statistics about the vector store."""
        if not self.available:
            return {"total_fields": 0, "data_models": [], "num_data_models": 0, "available": False}
            
        total_docs = self.collection.count()
        data_models = self.get_all_data_models()
        
        return {
            "total_fields": total_docs,
            "data_models": data_models,
            "num_data_models": len(data_models),
            "available": True
        }


def initialize_vector_store(knowledge_dir: str = "data/cim_knowledge", 
                           db_dir: str = "data/vector_db") -> CIMVectorStore:
    """Initialize and return a CIM vector store instance."""
    return CIMVectorStore(knowledge_dir, db_dir)
