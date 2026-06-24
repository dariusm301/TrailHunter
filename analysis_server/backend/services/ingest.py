from fastapi import HTTPException
from sqlalchemy.orm import Session
from services import validator
from services.storage import CollectionStorage
from services.processs import process_collection
from models.events import CollectionSummary


def handle_ingest(
    *,
    hostname: str,
    user_id: str,
    raw_body: bytes,
    x_collection_hash: str,
    x_collection_summary: str | None,
    db_session: Session,
) -> CollectionStorage:
    if not validator.verify_hash(raw_body, x_collection_hash):
        raise HTTPException(status_code=400, detail="Hash mismatch - data integrity check failed")

    collection_storage = CollectionStorage.create(
        hostname=hostname,
        user_id=user_id,
        db_session=db_session,
    )

    if x_collection_summary:
        summary = CollectionSummary.model_validate_json(x_collection_summary)
        collection_storage.save_summary(summary=summary.model_dump())

    if not collection_storage.save_raw(raw_body, x_collection_hash):
        raise HTTPException(status_code=400, detail="Failed to save data - hash mismatch")

    process_collection(collection_storage)
    return collection_storage