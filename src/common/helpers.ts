//src/helpers/helpers.ts
import { HttpException, HttpStatus } from '@nestjs/common';
// import { createClient, RedisClientType } from '@redis/client';


export class CommonHelpers {
    static readonly MAX_RETRIES = 3;
    static readonly DEFAULT_TTL = 300; // 5 minutes
    // public static redisClient: RedisClientType;

    // static initializeRedisClient(): RedisClientType {
    //     if (!this.redisClient) {
    //         this.redisClient = createClient({
    //             url: `redis://${process.env.REDIS_HOST || 'localhost'}:${process.env.REDIS_PORT || 6379}`,
    //         });
    //         this.redisClient.connect()
    //             .then(() => {
    //                 console.log('Connected to Redis successfully');
    //             })
    //             .catch((err) => {
    //                 console.error('Failed to connect to Redis:', err.message);
    //             });

    //         process.on('SIGINT', async () => {
    //             await this.redisClient.quit();
    //             console.log('Redis client disconnected');
    //             process.exit(0);
    //         });
    //     }
    //     return this.redisClient;
    // }

    static async retry<T>(operation: () => Promise<T>): Promise<T> {
        let attempt = 0;
        while (attempt < this.MAX_RETRIES) {
            try {
                console.log(`Attempt ${attempt + 1}`);
                return await operation();
            } catch (error) {
                attempt++;
                console.error(`Attempt ${attempt} failed: ${error.message}`);
                if (attempt === this.MAX_RETRIES) {
                    throw new HttpException(
                        `Operation failed after ${this.MAX_RETRIES} attempts: ${error.message}`,
                        HttpStatus.INTERNAL_SERVER_ERROR,
                    );
                }
                await new Promise((resolve) => setTimeout(resolve, 1000 * attempt));
            }
        }
        throw new HttpException('Unexpected error in retry logic', HttpStatus.INTERNAL_SERVER_ERROR);
    }

    // static async cacheOrFetch<T>(
    //     cacheKey: string, 
    //     fetchFn: () => Promise<T>, 
    //     ttl: number = this.DEFAULT_TTL, 
    //     setName?: string
    // ): Promise<T> {
    //     try {
    //         const cachedData = await this.redisClient.get(cacheKey);
    //         console.log(`Cache lookup for ${cacheKey}:`, cachedData ? 'Hit' : 'Miss');
    //         if (cachedData) {
    //             return JSON.parse(cachedData);
    //         }
    //         const data = await this.retry(fetchFn);
    //         console.log(`Setting cache for ${cacheKey} with TTL: ${ttl}s`);
    //         await this.redisClient.set(cacheKey, JSON.stringify(data), { EX: ttl });

    //         if (setName) {
    //             await this.redisClient.sAdd(setName, cacheKey);
    //             console.log(`Added ${cacheKey} to set: ${setName}`);
    //         }

    //         return data;
    //     } catch (error) {
    //         console.error(`Cache error for ${cacheKey}: ${error.message}`);
    //         return fetchFn();
    //     }
    // }

    // static async invalidateCache(cacheKeys: string[]): Promise<void> {
    //     for (const key of cacheKeys) {
    //         console.log(`Invalidating cache for key: ${key}`);
    //         await this.redisClient.del(key);
    //     }
    // }

    static transformDocument(document: any): any {
        return { ...document, _id: document._id.toString() };
    }
}
