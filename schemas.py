"""
Database Schemas for the Medical Payments App

Each Pydantic model name maps to a MongoDB collection with the lowercase name.
- Setting -> "setting"
- Service -> "service"
- Payment -> "payment"

"""
from typing import List, Optional
from pydantic import BaseModel, Field, EmailStr
from datetime import datetime


class Setting(BaseModel):
    practice_name: str = Field(..., description="Practice display name")
    practice_address: Optional[str] = Field(None, description="Practice address")
    practice_phone: Optional[str] = Field(None, description="Practice phone")
    practice_email: Optional[EmailStr] = Field(None, description="Email for notifications")


class Service(BaseModel):
    name: str = Field(..., description="Service name, e.g., Office visit")
    price: float = Field(..., ge=0, description="Service price in USD")
    category: Optional[str] = Field(None, description="Optional category")
    active: bool = Field(True, description="Whether service is visible")


class Payment(BaseModel):
    payment_id: str = Field(..., description="Unique payment ID (Stripe payment intent id)")
    created_at: Optional[datetime] = None
    patient_name: str = Field(...)
    patient_email: Optional[EmailStr] = None
    patient_phone: Optional[str] = None
    dob: Optional[str] = Field(None, description="Optional DOB as string")
    comment: Optional[str] = None
    services: List[dict] = Field(..., description="List of services with name and price or custom amount")
    amount: float = Field(..., ge=0, description="Total amount paid")
    status: str = Field(..., description="succeeded, processing, requires_payment_method, refunded, etc.")
    card_last4: Optional[str] = Field(None, description="Last 4 digits of the card")
    refunded: bool = Field(False, description="Marked refunded manually in admin UI")
