-- Scanner groups a user combined on one scan (empty = what scanType implies).
ALTER TABLE "Scan" ADD COLUMN "scanModules" TEXT[] DEFAULT ARRAY[]::TEXT[];
