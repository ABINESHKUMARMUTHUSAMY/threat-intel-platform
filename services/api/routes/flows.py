from fastapi import APIRouter

router = APIRouter()


@router.get("")
async def list_flows(limit: int = 100, offset: int = 0):
    return {"items": [], "limit": limit, "offset": offset, "total": 0}
