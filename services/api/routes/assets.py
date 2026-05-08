from fastapi import APIRouter

router = APIRouter()


@router.get("")
async def list_assets(limit: int = 100, offset: int = 0):
    return {"items": [], "limit": limit, "offset": offset, "total": 0}
