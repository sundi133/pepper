#!/bin/bash
# Run the evaluation harness inside the Pepper worker image (it carries the
# scanner tools), with this checkout's code mounted over the image's.
#   LLM_ENV=path/to/llm.env eval/run.sh --apps vampi --runs 1 --label baseline
# llm.env holds LLM_PROVIDER, LLM_BASE_URL, LLM_MODEL and LLM_API_KEY.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${LLM_ENV:?set LLM_ENV to a file with LLM_PROVIDER, LLM_BASE_URL, LLM_MODEL, LLM_API_KEY}"
IMAGE="${EVAL_IMAGE:-sundi133/pepper-worker:1.1.9}"
mkdir -p eval/.cache eval/results
docker run --rm --platform linux/amd64 --env-file "$LLM_ENV" \
  -e DATABASE_URL=postgresql://x:x@localhost:5432/x -e REDIS_URL=redis://localhost:6379 \
  -v "$PWD/src:/app/src:ro" -v "$PWD/eval:/app/eval" \
  --entrypoint sh "$IMAGE" -c "cd /app && npx tsx -r tsconfig-paths/register eval/run.ts $*"
