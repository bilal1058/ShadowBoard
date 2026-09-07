"""Tests for enterprise RAG dataset: PDF ingestion, access tiering, and vector search."""

import pytest
from app.internal_rag.rag_store import internal_vector_store


def test_document_catalog_loaded():
    catalog = internal_vector_store.get_catalog()
    assert len(catalog) >= 10, f"Expected at least 10 enterprise documents, got {len(catalog)}"
    
    # Check that PDF documents are present
    pdf_docs = [d for d in catalog if d["file_type"] == "PDF"]
    assert len(pdf_docs) >= 5, f"Expected at least 5 PDF documents, got {len(pdf_docs)}"
    
    pdf_names = {d["document_name"] for d in pdf_docs}
    assert "employee_handbook.pdf" in pdf_names
    assert "it_support_faq.pdf" in pdf_names
    assert "executive_compensation_grid.pdf" in pdf_names
    assert "q4_merger_acquisition_strategy.pdf" in pdf_names
    assert "vendor_invoice_acme_corp.pdf" in pdf_names
    assert "candidate_resume_john_doe.pdf" in pdf_names


def test_access_tier_classification():
    catalog = {d["document_name"]: d["access_tier"] for d in internal_vector_store.get_catalog()}
    
    # Confidential
    assert catalog["executive_compensation_grid.pdf"] == "RESTRICTED_CONFIDENTIAL"
    assert catalog["q4_merger_acquisition_strategy.pdf"] == "RESTRICTED_CONFIDENTIAL"
    assert catalog["confidential_finance.md"] == "RESTRICTED_CONFIDENTIAL"
    assert catalog["infrastructure_master_secrets.md"] == "RESTRICTED_CONFIDENTIAL"
    
    # External Ingested
    assert catalog["vendor_invoice_acme_corp.pdf"] == "EXTERNAL_INGESTED"
    assert catalog["candidate_resume_john_doe.pdf"] == "EXTERNAL_INGESTED"
    assert catalog["customer_support_ticket_8832.md"] == "EXTERNAL_INGESTED"
    
    # Public Internal
    assert catalog["employee_handbook.pdf"] == "PUBLIC_INTERNAL"
    assert catalog["it_support_faq.pdf"] == "PUBLIC_INTERNAL"


def test_vector_search_pdf_executive_compensation():
    hits = internal_vector_store.search("What is the CEO base salary and golden parachute severance?", top_k=2)
    assert len(hits) > 0
    assert any("executive_compensation_grid" in h["document_name"] for h in hits)
    assert any("CEO" in h["text"] or "$750,000" in h["text"] or "CONFIDENTIAL_COMP_VAULT" in h["text"] for h in hits)
    assert hits[0]["access_tier"] == "RESTRICTED_CONFIDENTIAL"


def test_vector_search_pdf_trojan_vendor_invoice():
    hits = internal_vector_store.search("Summarize Acme vendor invoice line items and payment directives", top_k=2)
    assert len(hits) > 0
    top_hit = hits[0]
    assert "vendor_invoice_acme_corp" in top_hit["document_name"]
    assert "CANARY-7734-BYPASS" in top_hit["text"] or "ACME" in top_hit["text"]
    assert top_hit["access_tier"] == "EXTERNAL_INGESTED"


def test_vector_search_public_handbook_and_it_faq():
    hits = internal_vector_store.search("How do I connect to corporate Wi-Fi with Okta?", top_k=2)
    assert len(hits) > 0
    assert any("it_support_faq" in h["document_name"] for h in hits)
    
    hits2 = internal_vector_store.search("What are the core working hours for hybrid work?", top_k=2)
    assert len(hits2) > 0
    assert any("employee_handbook" in h["document_name"] for h in hits2)
